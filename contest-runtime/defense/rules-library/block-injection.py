"""ctf_proxy BLOCK rules — injection family (SQLi, NoSQLi, command injection).

Defensive IPS filters for YOUR OWN service in an attack-defense CTF. Each method
of class Module is one rule; returning True drops the connection. Every rule
fails OPEN (any error -> False) so it can never take your service down.

Test the same pattern as a Suricata rule first ("Test on recent traffic") to be
sure it doesn't also match the scoring checker before you upload this.
"""


class Module:

    def blk_sqli(self, stream):
        """SQL injection: tautologies, UNION SELECT, stacked queries, time-based,
        schema enumeration. Narrow to a param/path if this is too broad."""
        try:
            import re
            m = stream.current_http_message
            if m is None:
                return False
            from urllib.parse import unquote_plus
            data = unquote_plus(unquote_plus(str(m.url or "") + "\n" + bytes(m.raw_body or b"").decode("latin-1", "replace")))
            return bool(re.search(
                r"union\s+(all\s+)?select"
                r"|['\"`]\s*\)?\s*(or|and)\s+['\"`\d(].{0,40}?(=|like|--|#)"
                r"|;\s*(drop|insert|update|delete|alter|create)\s"
                r"|\b(sleep|pg_sleep|benchmark|waitfor\s+delay)\s*\("
                r"|information_schema|sqlite_master|pg_catalog"
                r"|\b(load_file|extractvalue|updatexml)\s*\(",
                data, re.I))
        except Exception:
            return False

    def blk_nosqli(self, stream):
        """NoSQL (Mongo-style) injection: operator objects / bracket params /
        $where server-side JS."""
        try:
            import re
            m = stream.current_http_message
            if m is None:
                return False
            from urllib.parse import unquote_plus
            raw = str(m.url or "") + "\n" + bytes(m.raw_body or b"").decode("latin-1", "replace")
            dec = unquote_plus(raw)
            return bool(
                re.search(r"\[\s*\$(ne|eq|gt|gte|lt|lte|in|nin|regex|where|exists|or|and|not)\s*\]", dec, re.I)
                or re.search(r'"\$(ne|eq|gt|gte|lt|lte|in|nin|regex|where|exists|or|and)"\s*:', raw, re.I)
                or re.search(r"\$where|this\.\w+\s*(==|\.match)|function\s*\(\s*\)\s*\{", dec, re.I))
        except Exception:
            return False

    def blk_cmd_injection(self, stream):
        """OS command injection: a shell separator immediately followed by a
        common command, or an obvious reverse-shell / IFS-evasion construct."""
        try:
            import re
            m = stream.current_http_message
            if m is None:
                return False
            from urllib.parse import unquote_plus
            data = unquote_plus(unquote_plus(str(m.url or "") + "\n" + bytes(m.raw_body or b"").decode("latin-1", "replace")))
            return bool(re.search(
                r"(;|\||&&|`|\$\()\s*(id|whoami|uname|cat|ls|nc|ncat|curl|wget|bash|sh|python3?|perl|base64|env)\b"
                r"|/dev/tcp/|\bnc\s+(-\w+\s+)*-e\b|mkfifo\s|\bsh\s+-i\b"
                r"|\$\{IFS\}|\$IFS\$",
                data, re.I))
        except Exception:
            return False
