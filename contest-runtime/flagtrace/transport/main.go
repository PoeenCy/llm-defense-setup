// Flag-trace's offline transport adapter. Only stdin commands name capture files;
// stdout is a versioned JSON record stream. No listening/raw sockets are used.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/gopacket/gopacket/reassembly"
)

type Endpoint struct { IP string `json:"ip"`; Port uint16 `json:"port"`; Layer string `json:"layer"` }
type Config struct {
	Endpoints []Endpoint `json:"endpoints"`
	Idle int `json:"idle_seconds"`
	MaxAge int `json:"max_age_seconds"`
	MaxBytes int `json:"max_connection_bytes"`
	MaxConnections int `json:"max_connections"`
}
type Command struct { Path string `json:"path"`; ID string `json:"id"`; Source string `json:"source"`; Finalize bool `json:"finalize"` }
type Ref struct { File string `json:"file"`; Packet int `json:"packet"`; TS int64 `json:"ts"` }
type Span struct { Start int `json:"start"`; End int `json:"end"`; Ref Ref `json:"ref"` }
type Message struct { Data []byte `json:"data"`; TS int64 `json:"ts"`; EndTS int64 `json:"end_ts"`; Spans []Span `json:"spans"` }
type Turn struct { Direction string `json:"direction"`; Message }
type pending struct { Message; method string; issues []string }
type context struct { info gopacket.CaptureInfo }
func (c *context) GetCaptureInfo() gopacket.CaptureInfo { return c.info }
type engine struct {
	cfg Config; encoder *json.Encoder; streams map[string]*stream
	assembler *reassembly.Assembler; source string; clock time.Time
	packets int; ignored int; unsupported int
}
type stream struct {
	e *engine; id string; src, dst string; sport,dport uint16; reverse bool
	layer string; start int64; firstFile string; seq int; closed bool; raw bool
	issues []string; dirs [2]Message; requests []pending; turns []Turn; received int
}
func digest(v string) string { s:=sha256.Sum256([]byte(v)); return hex.EncodeToString(s[:]) }
func (e *engine) emit(v map[string]any) { v["schema_version"]=1; if err:=e.encoder.Encode(v); err!=nil { panic(err) } }
func (e *engine) endpoint(ip string, port uint16) string {
	for _, ep:=range e.cfg.Endpoints { if ep.IP==ip && ep.Port==port { return ep.Layer } }; return ""
}
func (e *engine) New(n,t gopacket.Flow,tcp *layers.TCP,ac reassembly.AssemblerContext) reassembly.Stream {
	ci:=ac.GetCaptureInfo(); ref:=ci.AncillaryData[0].(Ref)
	src,dst:=n.Src().String(),n.Dst().String(); sport,dport:=uint16(tcp.SrcPort),uint16(tcp.DstPort)
	layer:=e.endpoint(dst,dport); reverse:=false
	issues:=[]string{}
	if layer=="" { layer=e.endpoint(src,sport); if layer!="" { src,dst=dst,src; sport,dport=dport,sport; reverse=true } }
	if layer=="" { layer="unknown"; issues=append(issues,"ambiguous_direction") }
	if !tcp.SYN || tcp.ACK { issues=append(issues,"missing_syn") }
	id:=digest(fmt.Sprintf("%s|%s|%d|%s|%d|%d|%d",e.source,src,sport,dst,dport,ci.Timestamp.UnixMicro(),tcp.Seq))
	s:=&stream{e:e,id:id,src:src,dst:dst,sport:sport,dport:dport,reverse:reverse,layer:layer,start:ref.TS,firstFile:ref.File,issues:issues,raw:layer!="l7-http"}
	if len(e.streams)>=e.cfg.MaxConnections { s.issues=append(s.issues,"connection_limit"); s.closed=true; e.emit(map[string]any{"type":"warning","reason":"connection_limit","file":ref.File}); return s }
	if layer=="l7-https" { s.issues=append(s.issues,"encrypted") }
	e.streams[id]=s; return s
}
func (s *stream) Accept(tcp *layers.TCP,ci gopacket.CaptureInfo,dir reassembly.TCPFlowDirection,next reassembly.Sequence,start *bool,ac reassembly.AssemblerContext) bool {
	if s.closed { return false }; if !tcp.SYN { *start=true }; return true
}
func (s *stream) issue(v string) { for _,x:=range s.issues {if x==v{return}}; s.issues=append(s.issues,v) }
func appendMessage(m *Message, data []byte, ref Ref) {
	if len(m.Data)==0 { m.TS=ref.TS }; m.EndTS=ref.TS
	n:=len(m.Data); m.Data=append(m.Data,data...); m.Spans=append(m.Spans,Span{n,len(m.Data),ref})
}
func take(m *Message,n int) Message {
	out:=Message{Data:append([]byte(nil),m.Data[:n]...)}; rest:=[]Span{}
	for _,sp:=range m.Spans {
		if sp.Start<n { q:=sp; if q.End>n {q.End=n}; out.Spans=append(out.Spans,q); if len(out.Spans)==1 {out.TS=q.Ref.TS}; out.EndTS=q.Ref.TS }
		if sp.End>n {sp.Start=max(0,sp.Start-n); sp.End-=n; rest=append(rest,sp)}
	}
	m.Data=append([]byte(nil),m.Data[n:]...); m.Spans=rest
	if len(rest)>0 {m.TS=rest[0].Ref.TS; m.EndTS=rest[len(rest)-1].Ref.TS}; return out
}
func (s *stream) ReassembledSG(sg reassembly.ScatterGather,ac reassembly.AssemblerContext) {
	if s.closed{return}; dir,_,_,skip:=sg.Info(); if skip!=0 {s.issue("tcp_gap"); s.raw=true}
	d:=0; if dir==reassembly.TCPDirServerToClient {d=1}; if s.reverse {d=1-d}
	n,_:=sg.Lengths(); data:=sg.Fetch(n)
	left:=s.e.cfg.MaxBytes-s.received; if len(data)>left {data=data[:max(0,left)]; s.issue("connection_bytes_limit")}
	s.received+=len(data)
	for offset:=0;offset<len(data); {
		ref:=sg.CaptureInfo(offset).AncillaryData[0].(Ref)
		// Find the boundary of this packet's contiguous contribution.
		lo,hi:=offset+1,len(data)
		for lo<hi {mid:=(lo+hi)/2; r:=sg.CaptureInfo(mid).AncillaryData[0].(Ref); if r==ref {lo=mid+1}else{hi=mid}}
		appendMessage(&s.dirs[d],data[offset:lo],ref)
		if s.raw {m:=Message{}; appendMessage(&m,data[offset:lo],ref); label:="c2s";if d==1{label="s2c"};s.turns=append(s.turns,Turn{label,m})}
		offset=lo
	}
	if !s.raw {s.parse(false)}
	if s.received>=s.e.cfg.MaxBytes {s.finish("connection_bytes_limit")}
}

var incomplete=errors.New("incomplete")
// At connection end a message may stop mid-header or mid-body. It is returned
// whole with one of these, so it stays paired and is still scanned for flags.
var cutHeader=errors.New("incomplete_header")
var cutBody=errors.New("incomplete_body")
// frame uses net/http for framing, but slices original bytes rather than dumping
// parsed messages (which would normalize headers/chunking and lose evidence).
func frame(data []byte,request bool,method string,closed bool,limit int) (int,string,int,error) {
	if !bytes.Contains(data,[]byte("\r\n\r\n")) {if closed&&len(data)>0{return len(data),"",0,cutHeader};return 0,"",0,incomplete}
	raw:=bytes.NewReader(data); r:=bufio.NewReader(raw); var body io.ReadCloser; var code int; var m string
	if request {
		q,err:=http.ReadRequest(r);if err!=nil{return 0,"",0,err};body=q.Body;m=q.Method
	} else {
		q,err:=http.ReadResponse(r,&http.Request{Method:method});if err!=nil{return 0,"",0,err};body=q.Body;code=q.StatusCode
		if q.ContentLength<0 && len(q.TransferEncoding)==0 && q.Body!=http.NoBody && !closed {return 0,"",0,incomplete}
	}
	n,err:=io.Copy(io.Discard,io.LimitReader(body,int64(limit)+1))
	if n>int64(limit){return 0,"",0,errors.New("body_limit")}
	if err!=nil {if errors.Is(err,io.ErrUnexpectedEOF)||errors.Is(err,io.EOF){if !closed{return 0,"",0,incomplete};return len(data),m,code,cutBody};return 0,"",0,err}
	return len(data)-raw.Len()-r.Buffered(),m,code,nil
}
func (s *stream) parse(closed bool) {
	if bytes.HasPrefix(s.dirs[0].Data,[]byte("PRI * HTTP/2.0")) {s.issue("http2_unsupported");s.raw=true;return}
	for len(s.dirs[0].Data)>0 {
		n,method,_,err:=frame(s.dirs[0].Data,true,"",closed,s.e.cfg.MaxBytes)
		if err==incomplete {break}
		if err==cutHeader||err==cutBody {s.requests=append(s.requests,pending{take(&s.dirs[0],n),method,[]string{"req:"+err.Error()}});break}
		if err!=nil {s.issue("http_request_parse_error");s.raw=true;return}
		s.requests=append(s.requests,pending{take(&s.dirs[0],n),method,nil})
	}
	for len(s.requests)>0&&len(s.dirs[1].Data)>0 {
		req:=s.requests[0];n,_,code,err:=frame(s.dirs[1].Data,false,req.method,closed,s.e.cfg.MaxBytes)
		cut:=err==cutHeader||err==cutBody
		if err==incomplete {break};if err!=nil&&!cut {s.issue("http_response_parse_error");s.raw=true;return}
		if !cut&&code>=100&&code<200&&code!=101 {s.issue("informational_response");take(&s.dirs[1],n);continue}
		extra:=req.issues;if cut {extra=append(append([]string{},extra...),"resp:"+err.Error())}
		resp:=take(&s.dirs[1],n);s.requests=s.requests[1:];s.send(req.Message,resp,"http",nil,extra)
		if !cut&&(code==101||(req.method=="CONNECT"&&code>=200&&code<300)) {s.issue("upgraded_protocol");s.raw=true;return}
	}
}
func (s *stream) send(req,resp Message,proto string,turns []Turn,extra []string) {
	if req.TS==0 {req.TS=s.start};files:=map[string]bool{s.firstFile:true}
	for _,m:=range []Message{req,resp} {for _,sp:=range m.Spans{files[sp.Ref.File]=true}}
	ids:=[]string{};for f:=range files{ids=append(ids,f)};sort.Strings(ids)
	s.e.emit(map[string]any{"type":"transaction","conn_id":s.id,"seq":s.seq,"src_ip":s.src,"src_port":s.sport,"dst_ip":s.dst,"dst_port":s.dport,"start_ts":s.start,"layer":s.layer,"proto":proto,"request":req,"response":resp,"turns":turns,"pcaps":ids,"quality":append(append([]string{},s.issues...),extra...)})
	s.seq++
}
func (s *stream) finish(reason string) {
	if s.closed{return};if reason!="closed" {s.issue(reason)}
	if !s.raw{s.parse(true)}
	for _,req:=range s.requests {s.send(req.Message,Message{},"http",nil,append(append([]string{},req.issues...),"missing_response"))};s.requests=nil
	if len(s.dirs[0].Data)>0||len(s.dirs[1].Data)>0 {s.send(s.dirs[0],s.dirs[1],"tcp",s.turns,nil)}
	s.closed=true;delete(s.e.streams,s.id)
}
func (s *stream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {s.finish("closed");return true}

func (e *engine) read(cmd Command) error {
	f,err:=os.Open(cmd.Path);if err!=nil{return err};defer f.Close()
	r,err:=pcapgo.NewReader(f);if err!=nil{return err};e.source=cmd.Source
	link:=r.LinkType();if link!=layers.LinkTypeEthernet&&link!=layers.LinkTypeLinuxSLL&&link!=layers.LinkTypeRaw&&link!=layers.LinkTypeIPv4&&link!=layers.LinkTypeIPv6{return fmt.Errorf("unsupported linktype %d",link)}
	for index:=1;;index++ {
		data,ci,err:=r.ReadPacketData();if err==io.EOF{break};if err!=nil{return err};e.packets++
		if ci.Timestamp.After(e.clock){e.clock=ci.Timestamp}
		p:=gopacket.NewPacket(data,link,gopacket.Default)
		if ip:=p.Layer(layers.LayerTypeIPv4);ip!=nil {v:=ip.(*layers.IPv4);if v.FragOffset!=0||v.Flags&layers.IPv4MoreFragments!=0{e.unsupported++;continue}}
		if p.Layer(layers.LayerTypeIPv6Fragment)!=nil{e.unsupported++;continue}
		tl:=p.Layer(layers.LayerTypeTCP);if tl==nil||p.NetworkLayer()==nil{e.ignored++;continue};tcp:=tl.(*layers.TCP)
		n:=p.NetworkLayer().NetworkFlow();if e.endpoint(n.Src().String(),uint16(tcp.SrcPort))==""&&e.endpoint(n.Dst().String(),uint16(tcp.DstPort))=="" {e.ignored++;continue}
		ci.AncillaryData=[]any{Ref{cmd.ID,index,ci.Timestamp.UnixMicro()}}
		e.assembler.AssembleWithContext(n,tcp,&context{ci})
		for _,s:=range e.streams {if e.clock.UnixMicro()-s.start>int64(e.cfg.MaxAge)*1e6{s.finish("max_connection_age")}}
	}
	for _,s:=range e.streams {last:=max(s.dirs[0].EndTS,s.dirs[1].EndTS,s.start);if e.clock.UnixMicro()-last>int64(e.cfg.Idle)*1e6{s.finish("idle_timeout")}}
	e.assembler.FlushCloseOlderThan(e.clock.Add(-time.Duration(e.cfg.Idle)*time.Second))
	return nil
}
func main() {
	var cfg Config;in:=bufio.NewScanner(os.Stdin);in.Buffer(make([]byte,4096),1<<20)
	if !in.Scan(){return};if err:=json.Unmarshal(in.Bytes(),&cfg);err!=nil{panic(err)}
	if cfg.Idle<=0{cfg.Idle=120};if cfg.MaxAge<=0{cfg.MaxAge=600};if cfg.MaxBytes<=0{cfg.MaxBytes=8<<20};if cfg.MaxConnections<=0{cfg.MaxConnections=10000}
	e:=&engine{cfg:cfg,encoder:json.NewEncoder(os.Stdout),streams:map[string]*stream{}}
	e.assembler=reassembly.NewAssembler(reassembly.NewStreamPool(e));e.assembler.MaxBufferedPagesTotal=65536;e.assembler.MaxBufferedPagesPerConnection=128
	for in.Scan() {
		var cmd Command;if err:=json.Unmarshal(in.Bytes(),&cmd);err!=nil{panic(err)}
		if cmd.Finalize {for _,s:=range e.streams{s.finish("capture_end")};e.assembler.FlushAll()} else if err:=e.read(cmd);err!=nil {e.emit(map[string]any{"type":"error","file":cmd.ID,"error":err.Error()})}
		active:=[]string{};for _,s:=range e.streams{active=append(active,s.firstFile)};sort.Strings(active)
		e.emit(map[string]any{"type":"checkpoint","file":cmd.ID,"active_files":active,"packets":e.packets,"ignored":e.ignored,"unsupported":e.unsupported,"packet_time":e.clock.UnixMicro()})
	}
	if err:=in.Err();err!=nil&&!strings.Contains(err.Error(),"closed"){fmt.Fprintln(os.Stderr,err);os.Exit(1)}
}
