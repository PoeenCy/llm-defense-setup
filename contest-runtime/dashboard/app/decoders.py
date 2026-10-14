"""Flag-gated decode engine, defence-side.

A standalone port of the decoding matrix: it tries a wide set of encodings
(base64/32/58/85, hex, url, html, escapes, quoted-printable, gzip/zlib/deflate/
bz2/lzma/brotli/zstd, rot13, reverse, single-byte xor), stacked a few layers
deep, plus embedded-token scanning, and reports only the decodings that reveal
a flag the raw bytes did not already contain.

It lives here (detection + dashboard) rather than inside Tulip on purpose:
decoding happens on the defence stack, Tulip stays vanilla. The engine is pure
Python (stdlib only; brotli/zstd used if importable) and takes the flag regex
as a parameter, so detection passes its FLAG_REGEX env and the dashboard passes
services.json's flag.regex.
"""
import base64
import bz2
import codecs
import hashlib
import html
import lzma
import re
import time
import urllib.parse
import zlib
from typing import Callable, Iterator, List, Optional, Pattern, Tuple

# Bounds — the engine runs on untrusted, possibly huge payloads.
MAX_SIZE = 2 * 1024 * 1024       # cap on any single decoded result
MAX_DEPTH = 3                    # how many decodings may stack
MAX_NODES = 600                  # decodings attempted per blob
DEFAULT_BUDGET = 0.4             # seconds of work per blob
MAX_XOR_SWEEPS = 8              # how many blobs get a full 255-key xor sweep
MAX_XOR_SIZE = 64 * 1024        # xor sweep only on blobs up to this size
MAX_TEXT_SIZE = 256 * 1024      # str round-trip decoders only on text-sized blobs
MIN_RESULT = 4                  # ignore decodings shorter than this
MAX_REPEAT = 2                  # a codec may appear at most twice in one path


def compile_regex(pattern) -> Optional[Pattern]:
    """Accept a str/bytes/compiled pattern (or None) and return a bytes regex."""
    if pattern is None:
        return None
    if hasattr(pattern, "pattern"):  # already compiled
        pat = pattern.pattern
        return re.compile(pat if isinstance(pat, bytes) else pat.encode())
    if isinstance(pattern, str):
        pattern = pattern.encode()
    try:
        return re.compile(pattern)
    except re.error:
        return None


# --- single-step decoders ----------------------------------------------------
# Each takes bytes and returns bytes, or None when the input is not plausibly in
# that encoding. Raising is fine; the caller treats it as "not this encoding".

def _strip_space(data: bytes) -> bytes:
    return data.translate(None, delete=b" \t\r\n")


def _limit(data: bytes) -> Optional[bytes]:
    return None if len(data) > MAX_SIZE else data


_HTTP_START = re.compile(
    rb"^(?:HTTP/\d|(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT) \S)"
)


def d_http_body(data: bytes) -> Optional[bytes]:
    """Strip an HTTP header block and keep the body — every whole-blob decoder
    fails while the headers are still attached (a gzipped response reads as
    'HTTP/1.1 200 OK...', not gzip)."""
    if not _HTTP_START.match(data):
        return None
    for sep in (b"\r\n\r\n", b"\n\n"):
        at = data.find(sep)
        if at >= 0:
            return data[at + len(sep):] or None
    return None


def d_base64(data: bytes) -> Optional[bytes]:
    body = _strip_space(data)
    if len(body) < 8 or not re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", body):
        return None
    return base64.b64decode(body + b"=" * (-len(body) % 4))


def d_base64url(data: bytes) -> Optional[bytes]:
    body = _strip_space(data)
    if len(body) < 8 or not re.fullmatch(rb"[A-Za-z0-9\-_]+={0,2}", body):
        return None
    if b"-" not in body and b"_" not in body:
        return None
    return base64.urlsafe_b64decode(body + b"=" * (-len(body) % 4))


def d_base32(data: bytes) -> Optional[bytes]:
    body = _strip_space(data)
    if len(body) < 8 or not re.fullmatch(rb"[A-Za-z2-7]+=*", body):
        return None
    return base64.b32decode(body + b"=" * (-len(body) % 8), casefold=True)


def d_base85(data: bytes) -> Optional[bytes]:
    body = _strip_space(data)
    if len(body) < 8:
        return None
    return base64.b85decode(body)


def d_ascii85(data: bytes) -> Optional[bytes]:
    body = _strip_space(data)
    if len(body) < 8:
        return None
    return base64.a85decode(body, adobe=body.startswith(b"<~"))


_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_RE = re.compile(rb"[1-9A-HJ-NP-Za-km-z]+")


def d_base58(data: bytes) -> Optional[bytes]:
    body = _strip_space(data)
    if len(body) < 8 or len(body) > 4096 or not _B58_RE.fullmatch(body):
        return None
    number = 0
    for byte in body:
        number = number * 58 + _B58_ALPHABET.index(byte)
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(body) - len(body.lstrip(b"1"))) + decoded


def d_hex(data: bytes) -> Optional[bytes]:
    body = re.sub(rb"(?i)0x|[\s:,\-]", b"", data)
    if len(body) < 8 or len(body) % 2 or not re.fullmatch(rb"(?i)[0-9a-f]+", body):
        return None
    return bytes.fromhex(body.decode())


def d_url(data: bytes) -> Optional[bytes]:
    if b"%" not in data and b"+" not in data:
        return None
    return urllib.parse.unquote_to_bytes(data.replace(b"+", b" "))


def d_html(data: bytes) -> Optional[bytes]:
    if b"&" not in data:
        return None
    return html.unescape(data.decode("utf-8", "surrogateescape")).encode(
        "utf-8", "surrogateescape")


def d_escapes(data: bytes) -> Optional[bytes]:
    if b"\\x" not in data and b"\\u" not in data:
        return None
    return data.decode("unicode_escape").encode("latin-1", "backslashreplace")


import quopri  # noqa: E402  (grouped with the web decoders it belongs to)


def d_quopri(data: bytes) -> Optional[bytes]:
    if not re.search(rb"(?i)=[0-9a-f]{2}", data):
        return None
    return quopri.decodestring(data)


def d_rot13(data: bytes) -> Optional[bytes]:
    if len(data) > MAX_TEXT_SIZE:
        return None
    return codecs.encode(data.decode("latin-1"), "rot_13").encode("latin-1")


def d_reverse(data: bytes) -> Optional[bytes]:
    return data[::-1]


def _inflate(data: bytes, wbits: int) -> Optional[bytes]:
    return _limit(zlib.decompressobj(wbits).decompress(data, MAX_SIZE + 1))


def d_zlib(data: bytes) -> Optional[bytes]:
    if len(data) < 2 or data[0] & 0x0F != 8:
        return None
    return _inflate(data, 15)


def d_gzip(data: bytes) -> Optional[bytes]:
    return _inflate(data, 16 + 15)


def d_deflate(data: bytes) -> Optional[bytes]:
    return _inflate(data, -15)


def d_bz2(data: bytes) -> Optional[bytes]:
    if not data.startswith(b"BZh"):
        return None
    return _limit(bz2.BZ2Decompressor().decompress(data, MAX_SIZE + 1))


def d_lzma(data: bytes) -> Optional[bytes]:
    if not data.startswith((b"\xfd7zXZ", b"\x5d\x00\x00")):
        return None
    return _limit(lzma.LZMADecompressor().decompress(data, MAX_SIZE + 1))


def _load_optional() -> List[Tuple[str, Callable[[bytes], Optional[bytes]]]]:
    found = []
    try:
        import brotli
        found.append(("brotli", lambda d: _limit(brotli.decompress(d))))
    except ImportError:
        pass
    zstd = None
    try:
        from compression import zstd  # Python 3.14+
    except ImportError:
        try:
            import zstandard as zstd  # type: ignore
        except ImportError:
            pass
    if zstd is not None:
        found.append(("zstd", lambda d: _limit(zstd.decompress(d))))
    return found


# Order matters: the time budget is shared, so decoders that reject in a couple
# of byte comparisons go first and the ones that scan the whole blob go last.
DECODERS: List[Tuple[str, Callable[[bytes], Optional[bytes]]]] = [
    ("http-body", d_http_body),
    ("gzip", d_gzip), ("zlib", d_zlib), ("bz2", d_bz2), ("lzma", d_lzma),
    ("deflate", d_deflate),
    ("url", d_url), ("escapes", d_escapes), ("quopri", d_quopri), ("html", d_html),
    ("base64", d_base64), ("base64url", d_base64url), ("base32", d_base32),
    ("hex", d_hex), ("base85", d_base85), ("ascii85", d_ascii85), ("base58", d_base58),
    ("rot13", d_rot13), ("reverse", d_reverse),
]
_after = [n for n, _ in DECODERS].index("deflate") + 1
DECODERS[_after:_after] = _load_optional()

# Alphabet runs worth decoding on their own (a flag base64'd into one JSON field).
TOKEN_PATTERNS: List[Tuple[str, Pattern]] = [
    ("base64", re.compile(rb"[A-Za-z0-9+/]{16,}={0,2}")),
    ("base64url", re.compile(rb"[A-Za-z0-9\-_]{16,}={0,2}")),
    ("base32", re.compile(rb"[A-Z2-7]{16,}=*")),
    ("base58", re.compile(rb"[1-9A-HJ-NP-Za-km-z]{16,}")),
    ("hex", re.compile(rb"(?i)(?:[0-9a-f]{2}[\s:,\-]?){8,}")),
]

# Cheap pre-filter for the per-packet hot path: skip the engine unless the blob
# plausibly carries something encoded.
_LONG_RUN = re.compile(rb"[A-Za-z0-9+/_\-]{24,}|(?:[0-9a-fA-F]{2}[\s:,\-]?){12,}")
_COMPRESSED = re.compile(rb"\x1f\x8b|BZh|\xfd7zXZ|^\x78[\x01\x9c\xda]")


def looks_encoded(data: bytes) -> bool:
    """True if `data` might hold an encoded payload — a long base-N/hex run,
    compression magic, or a lot of non-text bytes. Lets a caller avoid running
    the full engine on every plain packet."""
    if not data:
        return False
    if _LONG_RUN.search(data) or _COMPRESSED.search(data[:4]) or b"\x1f\x8b" in data:
        return True
    sample = data[:2048]
    nonprint = sum(b < 9 or (13 < b < 32) or b >= 127 for b in sample)
    return nonprint > len(sample) * 0.3


class Finding:
    """One decoding that revealed a flag (or any decoding, with emit_all)."""

    __slots__ = ("path", "data", "flags")

    def __init__(self, path: str, data: bytes, flags: List[bytes]):
        self.path = path
        self.data = data
        self.flags = flags


class Engine:
    """Bounded recursive search over stacked decodings of one blob."""

    def __init__(self, flag_regex=None, *, emit_all: bool = False,
                 known_flags: Optional[set] = None, budget: float = DEFAULT_BUDGET,
                 xor: bool = True):
        self.flag_regex = compile_regex(flag_regex)
        self.emit_all = emit_all
        self.known_flags = set(known_flags or ())
        self.xor_enabled = xor
        self.nodes = 0
        self.xor_sweeps = 0
        self.deadline = time.monotonic() + budget

    def exhausted(self) -> bool:
        return self.nodes >= MAX_NODES or time.monotonic() > self.deadline

    def new_flags(self, data: bytes) -> List[bytes]:
        if self.flag_regex is None:
            return []
        out = []
        for m in self.flag_regex.findall(data):
            if m not in self.known_flags and m not in out:
                out.append(m)
        return out

    def search(self, data: bytes) -> List[Finding]:
        findings: List[Finding] = []
        seen = {hashlib.sha1(data).digest()}
        queue: List[Tuple[bytes, str, Tuple[str, ...], int]] = [(data, "", (), 0)]
        while queue and not self.exhausted():
            blob, path, used, depth = queue.pop(0)
            for label, codec, result in self.step(blob, used, depth):
                digest = hashlib.sha1(result).digest()
                if digest in seen:
                    continue
                seen.add(digest)
                sub_path = f"{path} -> {label}" if path else label
                flags = self.new_flags(result)
                if flags or self.emit_all:
                    findings.append(Finding(sub_path, result, flags))
                    self.known_flags.update(flags)
                if depth + 1 < MAX_DEPTH:
                    queue.append((result, sub_path, used + (codec,), depth + 1))
        return findings

    def step(self, blob: bytes, used: Tuple[str, ...], depth: int
             ) -> Iterator[Tuple[str, str, bytes]]:
        for name, decoder in DECODERS:
            if self.exhausted():
                return
            if used.count(name) >= MAX_REPEAT:
                continue
            self.nodes += 1
            try:
                result = decoder(blob)
            except Exception:
                continue
            if result and result != blob and len(result) >= MIN_RESULT:
                yield name, name, result
        if self.xor_enabled:
            for label, result in self.keyed(blob):
                yield label, "xor", result
        if depth == 0:
            yield from self.tokens(blob)

    def keyed(self, blob: bytes) -> Iterator[Tuple[str, bytes]]:
        if self.flag_regex is None or len(blob) > MAX_XOR_SIZE:
            return
        if self.xor_sweeps >= MAX_XOR_SWEEPS:
            return
        self.xor_sweeps += 1
        for key in range(1, 256):
            if time.monotonic() > self.deadline:
                return
            candidate = blob.translate(bytes(i ^ key for i in range(256)))
            if self.flag_regex.search(candidate):
                yield f"xor:0x{key:02x}", candidate

    def tokens(self, blob: bytes) -> Iterator[Tuple[str, str, bytes]]:
        decoders = dict(DECODERS)
        for name, pattern in TOKEN_PATTERNS:
            decoder = decoders[name]
            for match in pattern.finditer(blob):
                if self.exhausted():
                    return
                token = match.group(0)
                if token == blob:
                    continue
                self.nodes += 1
                try:
                    result = decoder(token)
                except Exception:
                    continue
                if result and len(result) >= MIN_RESULT:
                    yield f"token/{name}@{match.start()}", name, result


def find_flags(data: bytes, flag_regex, *, known=None, emit_all: bool = False,
               budget: float = DEFAULT_BUDGET, xor: bool = True) -> List[Finding]:
    """Decode `data` every plausible way and return the decodings that reveal a
    flag not already in `known` (or all decodings, with emit_all)."""
    return Engine(flag_regex, emit_all=emit_all, known_flags=known,
                  budget=budget, xor=xor).search(data)
