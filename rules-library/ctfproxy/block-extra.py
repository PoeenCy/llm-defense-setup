"""ctf_proxy BLOCK rules — extra families (LDAP, CRLF/header injection, XSS,
open redirect, generic payload markers).

Defensive IPS filters for your own service. One method = one rule; True drops
the connection; every rule fails OPEN. All rules match on REQUEST CONTENT
(URL / params / body) — never on User-Agent or source IP, because the scoring
checker can share those. Test as a Suricata rule first.
"""


def _data(stream):
    """URL-decoded url + body, or None. Self-contained (copy a method alone)."""
    m = stream.current_http_message
    if m is None:
        return None
    from urllib.parse import unquote_plus
    return unquote_plus(unquote_plus(str(m.url or "") + "\n" + bytes(m.raw_body or b"").decode("latin-1", "replace")))


class Module:

    def blk_ldap_injection(self, stream):
        """LDAP injection: filter-breaking ')(' / '*)(' sequences."""
        try:
            import re
            d = _data(stream)
            return d is not None and bool(re.search(r"\*\)\s*\(\s*[|&]|\)\s*\(\s*\w+\s*=\s*\*|\(\s*\|\s*\(", d))
        except Exception:
            return False

    def blk_crlf_injection(self, stream):
        """CRLF / HTTP response splitting in the URL (encoded newlines)."""
        try:
            import re
            m = stream.current_http_message
            if m is None:
                return False
            return bool(re.search(r"%0d%0a|%0a%0d|\r\n", str(m.url or ""), re.I))
        except Exception:
            return False

    def blk_xss(self, stream):
        """Reflected/stored XSS markers (matters when a service has an admin
        bot). Narrow to the vulnerable param if this hits normal content."""
        try:
            import re
            d = _data(stream)
            return d is not None and bool(re.search(
                r"<script[\s>]|javascript\s*:|<svg[^>]*onload|on(error|load|mouseover|focus)\s*=", d, re.I))
        except Exception:
            return False

    def blk_open_redirect_ssrf(self, stream):
        """A full URL sitting in a redirect/next/url/callback parameter —
        feeds SSRF and open-redirect. Content-based, not host-based."""
        try:
            import re
            m = stream.current_http_message
            if m is None:
                return False
            from urllib.parse import unquote_plus
            url = unquote_plus(str(m.url or ""))
            return bool(re.search(r"[?&](redirect|next|url|callback|return|dest|target|u)=\s*(https?:)?//", url, re.I))
        except Exception:
            return False

    def blk_jwt_alg_none(self, stream):
        """JWT with alg:none (auth bypass). Header content, not User-Agent."""
        try:
            import re
            m = stream.current_http_message
            if m is None:
                return False
            hdrs = " ".join(str(v) for v in (m.headers or {}).values())
            body = bytes(m.raw_body or b"").decode("latin-1", "replace")
            # base64url of {"alg":"none"...} / {"alg":"None"...}
            return bool(re.search(r"eyJ[\w-]*?(ImFsZyI6Im5vbmUi|ImFsZyI6Ik5vbmUi|iJub25lI|ICJub25lIg)", hdrs + body))
        except Exception:
            return False
