"""Small deterministic packet fixtures; no raw sockets or third-party generator."""
import base64
import json
import socket
import struct
from pathlib import Path

BASE = 1800000000
SERVER = "10.60.1.1"


def config():
    return {"team_id": "team-01", "vulnbox": {"ip": SERVER}, "flag": {"regex": r"FLAG\{[A-Za-z0-9_]+\}"},
            "game": {"id": "fixture", "start_time": "2027-01-15T08:00:00Z", "tick_seconds": 120, "checker_ips": ["10.60.0.1"]},
            "teams": [{"id": "team-05", "name": "Five", "ips": ["10.60.5.1", "10.61.5.1"]},
                      {"id": "team-09", "name": "Nine", "ips": ["10.60.9.1"]}],
            "services": [{"name": "notes", "port": 8080, "proto": "tcp", "layer": "l7-http"}],
            "flagtrace": {"enabled": True, "min_free_gb": 0, "decode_budget": .01,
                          "trace": {"enabled": True}}}


def packet(src, dst, sport, dport, seq, ack, flags, data=b""):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xffffffff, ack & 0xffffffff, 5 << 4, flags, 65535, 0, 0) + data
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return b"\x01" * 6 + b"\x02" * 6 + b"\x08\x00" + ip + tcp


class Connection:
    def __init__(self, ip="10.60.5.1", port=51234, clock=0, service=8080):
        self.ip, self.port, self.service, self.clock = ip, port, service, clock
        self.cseq, self.sseq = 1000, 5000
        self.packets = []
        self.send(b"", flags=2)
        self.cseq += 1
        self.send(b"", server=True, flags=18)
        self.sseq += 1
        self.send(b"", flags=16)

    def send(self, data, server=False, flags=24):
        if server:
            raw = packet(SERVER, self.ip, self.service, self.port, self.sseq, self.cseq, flags, data)
            self.sseq += len(data)
        else:
            raw = packet(self.ip, SERVER, self.port, self.service, self.cseq, self.sseq, flags, data)
            self.cseq += len(data)
        self.clock += 1000
        self.packets.append((self.clock, raw))
        return self.packets[-1]

    def close(self):
        self.send(b"", flags=17)
        self.cseq += 1
        self.send(b"", server=True, flags=17)
        self.sseq += 1
        self.send(b"", flags=16)


def request(path, method="GET", body=b"", headers=()):
    lines = [f"{method} {path} HTTP/1.1", "Host: notes", f"Content-Length: {len(body)}"]
    lines += [f"{k}: {v}" for k, v in headers]
    return "\r\n".join(lines).encode() + b"\r\n\r\n" + body


def response(body=b"", headers=(), status=200):
    lines = [f"HTTP/1.1 {status} OK", f"Content-Length: {len(body)}"] + [f"{k}: {v}" for k, v in headers]
    return "\r\n".join(lines).encode() + b"\r\n\r\n" + body


def write_pcap(path, packets):
    with Path(path).open("wb") as f:
        f.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for us, raw in packets:
            sec, fraction = divmod(us, 1_000_000)
            f.write(struct.pack("<IIII", BASE + sec, fraction, len(raw), len(raw)))
            f.write(raw)


def notes_packets():
    c = Connection()
    c.send(request("/register", "POST", b"user=k8x2pv&pass=q91zzr", [("Content-Type", "application/x-www-form-urlencoded")]))
    c.send(response(b'{"ok":true}', [("Content-Type", "application/json")]), server=True)
    c.send(request("/login", "POST", b"user=k8x2pv&pass=q91zzr", [("Content-Type", "application/x-www-form-urlencoded")]))
    c.send(response(b"ok", [("Set-Cookie", "session=ab12cd9f; HttpOnly")]), server=True)
    c.send(request("/upload", "POST", b"name=../../notes/7731.txt", [("Content-Type", "application/x-www-form-urlencoded"), ("Cookie", "session=ab12cd9f")]))
    c.send(response(b'{"id":"f93a1c"}', [("Content-Type", "application/json")]), server=True)
    c.send(request("/files/f93a1c", headers=[("Cookie", "session=ab12cd9f")]))
    flag = response(b"FLAG{stolen_from_notes}")
    c.send(flag[:-8], server=True)
    c.send(flag[-8:], server=True)
    c.close()
    return c.packets


# ── Phase 2 fixtures ────────────────────────────────────────────────────────
# Expectations are written as request meaning (method, path), never as row IDs:
# the point is that the engine found the right *steps* and the right reason for
# each link, not that it produced a particular identifier.
FORM_CT = [("Content-Type", "application/x-www-form-urlencoded")]
JSON_CT = [("Content-Type", "application/json")]

# Each step of the notes chain, one per TCP connection. If these four are found
# together it cannot be because they shared a connection.
NOTES_STEPS = [("POST", "/register"), ("POST", "/login"), ("POST", "/upload"), ("GET", "/files/f93a1c")]
NOTES_EDGES = [
    # (src step, src category, dst step, dst category, kind)
    (("POST", "/login"), "cookie", ("POST", "/upload"), "cookie", "response_to_request"),
    (("POST", "/login"), "cookie", ("GET", "/files/f93a1c"), "cookie", "response_to_request"),
    (("POST", "/upload"), "json", ("GET", "/files/f93a1c"), "path", "response_to_request"),
    (("POST", "/register"), "form", ("POST", "/login"), "form", "request_reuse"),
]
# Values in the chain that no earlier message explains. The traversal payload is
# the interesting one: B6 (P2.4) is where it becomes a target, not here.
NOTES_UNEXPLAINED = ["../../notes/7731.txt", "7731", "k8x2pv", "q91zzr"]


def step_chain(port, clock, steps, ip="10.60.5.1", service=8080):
    """One connection per step, so each request stands on its own evidence."""
    packets = []
    for n, (req, resp) in enumerate(steps):
        c = Connection(ip=ip, port=port + n, clock=clock + n * 10_000, service=service)
        c.send(req)
        c.send(resp, server=True)
        c.close()
        packets += c.packets
    return packets


def notes_split_packets(session="ab12cd9f", file_id="f93a1c", user="k8x2pv", password="q91zzr",
                        flag=b"FLAG{stolen_from_notes}", port=51101, clock=1000, ip="10.60.5.1"):
    """register → login → upload → read, each on its own connection."""
    return step_chain(port, clock, [
        (request("/register", "POST", f"user={user}&pass={password}".encode(), FORM_CT),
         response(b'{"ok":true}', JSON_CT)),
        (request("/login", "POST", f"user={user}&pass={password}".encode(), FORM_CT),
         response(b"ok", [("Set-Cookie", f"session={session}; HttpOnly")])),
        (request("/upload", "POST", b"name=../../notes/7731.txt", FORM_CT + [("Cookie", f"session={session}")]),
         response(b'{"id":"%s"}' % file_id.encode(), JSON_CT)),
        (request(f"/files/{file_id}", headers=[("Cookie", f"session={session}")]),
         response(flag)),
    ], ip=ip)


def noise_packets(port=51201, clock=25_000, ip="10.60.5.1", paths=("/static/app.js", "/healthz")):
    """Traffic with nothing in common with the chain, interleaved in time."""
    return step_chain(port, clock, [(request(p), response(b"body of " + p.encode())) for p in paths], ip=ip)


def after_anchor_packets(file_id="f93a1c", session="ab12cd9f", port=51301, clock=200_000, ip="10.60.5.1"):
    """A request later than the flag-out. It shares values with the chain, so it
    is only excluded if the engine really refuses to look forward in time."""
    return step_chain(port, clock, [
        (request(f"/files/{file_id}", headers=[("Cookie", f"session={session}")]), response(b"already read")),
    ], ip=ip)


def two_scripts_packets():
    """Two chains from one team on one service, interleaved, different sessions."""
    first = notes_split_packets(session="s1aa11bb", file_id="f1aaaa", user="u1xxxxx", password="p1yyyyy",
                                flag=b"FLAG{first_script}", port=51401, clock=1000)
    second = notes_split_packets(session="s2cc22dd", file_id="f2bbbb", user="u2xxxxx", password="p2yyyyy",
                                 flag=b"FLAG{second_script}", port=51501, clock=6000)
    return sorted(first + second)


def shared_token_packets(session="sharedsess01", flag=b"FLAG{shared_value}"):
    """Four sources — two mapped teams and two unmapped IPs — using the same
    session value and each reading a flag."""
    packets = []
    for n, ip in enumerate(("10.60.5.1", "10.60.9.1", "10.60.88.1", "10.60.89.1")):
        packets += step_chain(51601 + n * 10, 1000 + n * 50_000, [
            (request("/login", "POST", b"user=sameuser01&pass=samepass01", FORM_CT),
             response(b"ok", [("Set-Cookie", f"session={session}; HttpOnly")])),
            (request("/files/shared01", headers=[("Cookie", f"session={session}")]), response(flag)),
        ], ip=ip)
    return sorted(packets)


def multi_flag_packets(session="mf11aa22"):
    """One response with two flags, then a second read on the same session:
    one profile per anchor, and the first anchor holds both flags."""
    return step_chain(51701, 1000, [
        (request("/login", "POST", b"user=mfuser001&pass=mfpass001", FORM_CT),
         response(b"ok", [("Set-Cookie", f"session={session}; HttpOnly")])),
        (request("/files/both", headers=[("Cookie", f"session={session}")]),
         response(b"FLAG{first_of_two} and FLAG{second_of_two}")),
        (request("/files/third", headers=[("Cookie", f"session={session}")]),
         response(b"FLAG{third_one}")),
    ])


def degraded_chain_packets(session="dg11aa22", flag=b"FLAG{after_decode}"):
    """A chain whose evidence is imperfect: the upload response is cut off mid
    body, and the flag is only visible after gzip decoding."""
    import gzip
    packets = step_chain(51801, 1000, [
        (request("/login", "POST", b"user=dguser001&pass=dgpass001", FORM_CT),
         response(b"ok", [("Set-Cookie", f"session={session}; HttpOnly")])),
    ])
    cut = Connection(ip="10.60.5.1", port=51811, clock=20_000)
    cut.send(request("/upload", "POST", b"name=../../notes/7731.txt", FORM_CT + [("Cookie", f"session={session}")]))
    cut.send(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4000\r\n\r\n{"id":"dgfile"}',
             server=True)
    cut.close()
    read = Connection(ip="10.60.5.1", port=51812, clock=40_000)
    read.send(request("/files/dgfile", headers=[("Cookie", f"session={session}")]))
    read.send(response(gzip.compress(flag), [("Content-Encoding", "gzip")]), server=True)
    read.close()
    return sorted(packets + cut.packets + read.packets)


def checker_putflag_packets(ticks=2, tick_us=120_000_000, ip="10.60.0.1"):
    """Checker putflag sessions: the source of flag-ID candidates, and traffic
    that must never be linked into a team's chain."""
    packets = []
    for tick in range(ticks):
        c = Connection(ip=ip, port=52000 + tick, clock=tick * tick_us + 1000)
        c.send(request("/register", "POST", f"user=chk{tick}user&role=writer".encode(), FORM_CT))
        c.send(response(b"ok", [("Set-Cookie", f"session=sess{tick}abc")]), server=True)
        c.send(request("/put", "POST", f"title=static&body=FLAG{{tick{tick}_put}}".encode(),
                       FORM_CT + [("Cookie", f"session=sess{tick}abc")]))
        c.send(response(f'{{"id": {500 + tick}}}'.encode(), JSON_CT), server=True)
        c.close()
        packets += c.packets
    return packets


def checker_notes_packets(puts, ip="10.60.0.1", tick_us=120_000_000):
    """Checker putflag sessions of the notes service. Each stores one flag and
    gets back the note ID the service assigned: the flag ID an attacker needs,
    different every tick. `puts` is [(tick, note_id, flag)]."""
    packets = []
    for n, (tick, note_id, flag) in enumerate(puts):
        c = Connection(ip=ip, port=52500 + n, clock=tick * tick_us + 1000)
        c.send(request("/register", "POST", f"user=chk{tick}u{n}&pass=chkpw{tick}x{n}".encode(), FORM_CT))
        c.send(response(b"ok", [("Set-Cookie", f"session=chks{tick}x{n}")]), server=True)
        c.send(request("/put", "POST", b"body=" + flag, FORM_CT + [("Cookie", f"session=chks{tick}x{n}")]))
        c.send(response(b'{"id":"%s"}' % note_id.encode(), JSON_CT), server=True)
        c.close()
        packets += c.packets
    return packets


def encoded_target_packets(clock=121_000_000):
    """Two one-request reads whose flag ID sits inside an encoding: base64 of a
    path (rebuildable around a template) and a JWT claim (not re-signable)."""
    claims = base64.urlsafe_b64encode(b'{"note":"7731","u":"x"}').rstrip(b"=").decode()
    jwt = "eyJhbGciOiJIUzI1NiJ9." + claims + ".c2lnbmF0dXJlX2hlcmU"
    path = base64.b64encode(b"/notes/7731.txt").decode()
    return step_chain(53301, clock, [
        (request(f"/read?f={path}"), response(b"FLAG{inside_base64}")),
        (request("/jwtread", headers=[("Authorization", "Bearer " + jwt)]), response(b"FLAG{inside_jwt}")),
    ])


def graphql_echo_packets(user="u947b8e9b3326e9ec094e", password="pba88ecc34b3a330164491e",
                         token="tk5f0c2e9a7b3d41e6a8c9f0d2b4e6a8c1", flag=b"FLAG{graphql_vault}"):
    """Shape of the real dataset B: every step is POST /graphql with a query
    text, register echoes the username back, login returns a bearer token.
    The echo must not hide that the attacker made the username up."""
    def gql(query, variables, headers=()):
        return request("/graphql", "POST", json.dumps({"query": query, "variables": variables}).encode(),
                       JSON_CT + list(headers))
    return step_chain(53501, 1000, [
        (gql("mutation X($user: UserInput!){ signup(user: $user){ username } }",
             {"user": {"name": user, "password": password}}),
         response(json.dumps({"data": {"signup": {"username": user}}}).encode(), JSON_CT)),
        (gql("mutation L($key: String!, $password: String!){ login(key: $key, password: $password){ token } }",
             {"key": user, "password": password}),
         response(json.dumps({"data": {"login": {"token": token}}}).encode(), JSON_CT)),
        (gql("query { vault { secret } }", {}, [("Authorization", "Bearer " + token)]),
         response(json.dumps({"data": {"vault": {"secret": flag.decode()}}}).encode(), JSON_CT)),
    ])


def html_payload_packets(session="hx11aa22"):
    """Repeated fields, a dotted JSON key and captured HTML/script content: the
    evidence viewer has to render this as text, never execute it."""
    body = (b'<script>alert("xss")</script><img src=x onerror=alert(1)>'
            b'FLAG{html_payload_flag}')
    return step_chain(51901, 1000, [
        (request("/login?next=/a&next=/b", "POST", b"user=hxuser001&pass=hxpass001&user=hxuser002", FORM_CT),
         response(b'{"a.b":"first1234","a.b":"second123"}', JSON_CT + [("Set-Cookie", f"session={session}")])),
        (request("/render", "POST", b'{"tpl":"<script>x</script>","id":"hxfile01"}',
                 JSON_CT + [("Cookie", f"session={session}")]),
         response(b'{"id":"hxfile01"}', JSON_CT)),
        (request("/files/hxfile01", headers=[("Cookie", f"session={session}")]), response(body)),
    ])


def bearer_token_packets(token="tok7fa3c9e1b55d4e2a8c0f16229adb3e77", flag=b"FLAG{token_vault}"):
    """Login returns an opaque access_token in JSON; the next request carries it
    as `Authorization: Bearer <token>` to read the flag. The whole token — not
    just fragments of it — must link the read back to the login, i.e. the auth
    scheme word must be stripped before matching."""
    return step_chain(53101, 1000, [
        (request("/login", "POST", b"user=vaultuser01&pass=vaultpass01", FORM_CT),
         response(b'{"access_token":"%s"}' % token.encode(), JSON_CT)),
        (request("/vault", headers=[("Authorization", "Bearer " + token)]), response(flag)),
    ])


def old_account_packets(session="oa11bb22", tick_us=120_000_000):
    """The account was registered ticks before it was used, and two logins
    handed out the same session value. The read must take the nearest login
    before it and list the other as an alternative; the index lookup has to
    reach back to the registration without scanning the game."""
    return sorted(step_chain(52101, 1000, [
        (request("/register", "POST", b"user=oauser001&pass=oapass001", FORM_CT), response(b'{"ok":true}', JSON_CT)),
    ]) + step_chain(52111, 3 * tick_us, [
        (request("/login", "POST", b"user=oauser001&pass=oapass001", FORM_CT),
         response(b"ok", [("Set-Cookie", f"session={session}; HttpOnly")])),
    ]) + step_chain(52121, 5 * tick_us, [
        (request("/login", "POST", b"user=oauser001&pass=oapass001", FORM_CT),
         response(b"ok", [("Set-Cookie", f"session={session}; HttpOnly")])),
        (request("/files/oa0123ff", headers=[("Cookie", f"session={session}")]), response(b"FLAG{old_account}")),
    ]))


def stalled_register_packets(session="st11aa22"):
    """The registration's response stalls, so Phase 1 only emits that
    transaction when the connection ends, after the flag-out was traced.
    The first analysis cannot see it; a retrace after it lands can."""
    register = Connection(port=52201, clock=1000)
    register.send(request("/register", "POST", b"user=stuser001&pass=stpass001", FORM_CT))
    register.send(b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nstill", server=True)
    return sorted(register.packets + step_chain(52202, 20_000, [
        (request("/login", "POST", b"user=stuser001&pass=stpass001", FORM_CT),
         response(b"ok", [("Set-Cookie", f"session={session}")])),
        (request("/files/st0123ff", headers=[("Cookie", f"session={session}")]), response(b"FLAG{stalled}")),
    ]))


def image_sharing_packets(reads=2):
    """Shape of the real DTFC capture (dataset A): a page and a manifest whose
    text and JSON contain the words of the endpoint name ("image", "manifest"),
    then one-request file reads that all send the same constant parameter.
    Each read is a complete exploit on its own; nothing links them."""
    page = (b'<html><link rel="manifest" href="/manifest.json">'
            b'<a href="/image-sharing/">image sharing</a></html>')
    return step_chain(52301, 1000, [
        (request("/"), response(page, [("Content-Type", "text/html")])),
        (request("/manifest.json"), response(b'{"icons":[{"src":"/icon.png","type":"image/png"}]}', JSON_CT)),
    ] + [(request("/image-sharing/?f=L2ZsYWcvZmxhZw=="), response(b"FLAG{image_read_%d}" % n)) for n in range(reads)])


if __name__ == "__main__":
    import sys
    root = Path(sys.argv[1])
    root.mkdir(parents=True, exist_ok=True)
    (root / "services.json").write_text(json.dumps(config(), indent=2))
    write_pcap(root / "notes.pcap", notes_packets())
    write_pcap(root / "notes-split.pcap", sorted(notes_split_packets() + noise_packets() + after_anchor_packets()))
    write_pcap(root / "two-scripts.pcap", two_scripts_packets())
    write_pcap(root / "degraded.pcap", degraded_chain_packets())
