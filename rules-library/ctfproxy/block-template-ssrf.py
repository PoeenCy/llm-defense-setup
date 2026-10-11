"""ctf_proxy BLOCK rules — SSTI, SSRF, path traversal / LFI.

Defensive IPS filters for your own service. One method = one rule; True drops
the connection; every rule fails OPEN. Test as a Suricata rule first.
"""


class Module:

    def blk_ssti(self, stream):
        """Server-side template injection: template delimiters containing a
        call/attr/dunder, or a known Python/Java/Node template gadget."""
        try:
            import re
            m = stream.current_http_message
            if m is None:
                return False
            from urllib.parse import unquote_plus
            data = unquote_plus(unquote_plus(str(m.url or "") + "\n" + bytes(m.raw_body or b"").decode("latin-1", "replace")))
            return bool(re.search(
                r"\{\{[^}]*?([(*]|__)[^}]*?\}\}"              # {{ ... ( / __ ... }}
                r"|(\{\{|\$\{|#\{|<%=?)\s*\d+\s*\*\s*\d+"     # {{7*7}} style probe
                r"|__(class|mro|subclasses|globals|builtins|import)__"
                r"|\b(lipsum|cycler|request\.application|config\.items)\b"
                r"|freemarker\.template|getRuntime\s*\(|T\s*\(\s*java\.lang"
                r"|process\.mainModule|constructor\s*\.\s*constructor|child_process",
                data, re.I))
        except Exception:
            return False

    def blk_ssrf(self, stream):
        """SSRF: a URL in the request pointing at loopback, cloud-metadata, an
        obfuscated-IP form, or a dangerous scheme (file/gopher/dict/...)."""
        try:
            import re
            m = stream.current_http_message
            if m is None:
                return False
            from urllib.parse import unquote_plus
            data = unquote_plus(unquote_plus(str(m.url or "") + "\n" + bytes(m.raw_body or b"").decode("latin-1", "replace")))
            return bool(re.search(
                r"(https?|ftp|gopher|dict|ldap|tftp)://(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1?\])"
                r"|169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200"
                r"|://(\d{8,10}|0x[0-9a-f]{8})"               # decimal / hex IP
                r"|(file|gopher|dict|jar|php|expect|phar|netdoc)://"
                r"|://[^/\s]*(host\.docker\.internal|kubernetes\.default|\.svc\.cluster\.local)",
                data, re.I))
        except Exception:
            return False

    def blk_traversal(self, stream):
        """Path traversal / local file inclusion: ../ sequences, sensitive file
        names, encoding tricks."""
        try:
            import re
            m = stream.current_http_message
            if m is None:
                return False
            from urllib.parse import unquote_plus
            raw = str(m.url or "") + "\n" + bytes(m.raw_body or b"").decode("latin-1", "replace")
            dec = unquote_plus(unquote_plus(raw))
            return bool(re.search(
                r"\.\.[/\\]+\.\.[/\\]"
                r"|/etc/(passwd|shadow|hosts)"
                r"|/proc/(self|\d+)/(environ|cmdline|cwd|fd|maps|root)"
                r"|\.\./\.env|/\.ssh/(id_|authorized_keys)",
                dec, re.I) or bool(re.search(r"%00|%2500|%c0%ae|%252e", raw, re.I)))
        except Exception:
            return False
