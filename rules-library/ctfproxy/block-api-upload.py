"""ctf_proxy BLOCK rules — GraphQL abuse, malicious upload, deserialization/XXE.

Defensive IPS filters for your own service. One method = one rule; True drops
the connection; every rule fails OPEN. Test as a Suricata rule first.
"""
from urllib.parse import unquote_plus


class Module:

    def blk_graphql_abuse(self, stream):
        """GraphQL: introspection dump (__schema) or a batched-query array
        (used for brute force / rate-limit bypass). NOTE: if your own frontend
        uses introspection, narrow this to unexpected clients or remove it."""
        try:
            import re
            m = stream.current_http_message
            if m is None:
                return False
            body = bytes(m.raw_body or b"").decode("latin-1", "replace")
            url = str(m.url or "")
            return bool(
                re.search(r"__schema\b", body + url, re.I)
                or re.match(r"\s*\[\s*\{\s*\"(query|operationName)\"", body))
        except Exception:
            return False

    def blk_upload_webshell(self, stream):
        """Upload of an executable script, or an executable-code marker in the
        body (server-side script tags with code-exec constructs)."""
        try:
            import re
            m = stream.current_http_message
            if m is None:
                return False
            body = bytes(m.raw_body or b"").decode("latin-1", "replace")
            return bool(
                re.search(r'filename="[^"]*\.(php\d?|phtml|phar|pht|jsp|jspx|asp|aspx|cgi|pl)(\.|")', body, re.I)
                or re.search(r'filename="[^"]*(\.\./|\.htaccess|web\.config)', body, re.I)
                or re.search(r"<\?(php|=).{0,200}(system|exec|passthru|shell_exec|eval|popen|\$_(GET|POST|REQUEST))",
                             body, re.I | re.S))
        except Exception:
            return False

    def blk_deser_xxe(self, stream):
        """Insecure deserialization / XXE / prototype pollution markers in the
        body: Python pickle, PHP/Java serialized objects, unsafe YAML tags,
        XML external entities, __proto__."""
        try:
            import re
            m = stream.current_http_message
            if m is None:
                return False
            body = bytes(m.raw_body or b"").decode("latin-1", "replace")
            dec = unquote_plus(body)
            return bool(re.search(
                r"O:\d+:\"\w+\":\d+:\{"                       # PHP object
                r"|rO0AB|\xac\xed\x00\x05"                    # Java serialized
                r"|!!python/(object|apply)|!ruby/object"      # unsafe YAML
                r"|<!ENTITY\s+%?\s*\w+\s+(SYSTEM|PUBLIC)"     # XXE
                r"|__proto__|constructor\s*(\.|\[)\s*['\"]?prototype",
                dec, re.I))
        except Exception:
            return False
