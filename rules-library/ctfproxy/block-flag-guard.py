"""ctf_proxy BLOCK rules — stop flags leaving the service in a RESPONSE.

This is an OUTBOUND filter: it looks at what the service is about to send back.
Use it as web_out.py (ctf_proxy's out-module), NOT web_in.py, because it
inspects responses. One method = one rule; True drops the connection; fails OPEN.

DANGER: the scoring checker legitimately reads ONE flag per request. A rule that
blocks a single flag in a response WILL break scoring. So these rules only fire
on an ABNORMAL number of flags (mass dump) or on the decoy honeytoken, which the
checker never touches. Edit FLAG_RE / THRESHOLD / HONEYTOKEN for your arena
(CONFIG tab shows the current flag regex and honeytoken).
"""

FLAG_RE = r"[A-Z0-9]{31}="          # keep in sync with services.json -> flag.regex
THRESHOLD = 3                        # this many flags in one response = dump
HONEYTOKEN = "HONEYTOKEN000000000000000000000="   # services.json -> honeytoken.flag


class Module:

    def blk_flag_massdump(self, stream):
        """Block a response carrying THRESHOLD+ flags at once (data dump). A
        normal checker read returns a single flag and is not affected."""
        try:
            import re
            m = stream.current_http_message
            if m is None:
                return False
            body = bytes(m.raw_body or b"").decode("latin-1", "replace")
            return len(re.findall(FLAG_RE, body)) >= THRESHOLD
        except Exception:
            return False

    def blk_honeytoken_out(self, stream):
        """Block the decoy honeytoken from ever leaving. The checker never reads
        the decoy, so any outbound honeytoken is an attacker — safe to block."""
        try:
            m = stream.current_http_message
            if m is None:
                return False
            body = bytes(m.raw_body or b"").decode("latin-1", "replace")
            return HONEYTOKEN in body
        except Exception:
            return False
