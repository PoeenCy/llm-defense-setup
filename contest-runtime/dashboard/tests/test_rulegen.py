"""Run: python3 -m pytest dashboard/tests -q   (or: python3 dashboard/tests/test_rulegen.py)"""
import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.rulegen import ctfproxy, suricata  # noqa: E402

TEMPLATE = '''from src.stream import Stream, TCPStream, HTTPStream

class Module():

    def execute(self, stream: Stream):
        attacks = [getattr(Module, a) for a in dir(Module) if callable(getattr(Module, a)) and not a.startswith('__') and a != "execute"]
        for attack in attacks:
            try:
                if attack(self, stream):
                    return attack.__name__
            except IndexError:
                pass
        return None
'''


def test_escape_content_specials_become_hex():
    assert suricata.escape_content('a"b;c\\d|e') == "a|22|b|3B|c|5C|d|7C|e"
    assert suricata.escape_content("../../etc/passwd") == "../../etc/passwd"
    assert suricata.escape_content("x\r\ny") == "x|0D 0A|y"


def test_next_sid_skips_foreign_ranges():
    rules = "alert tcp any any -> any any (sid:1000001;)\nalert http any any -> any any (sid:9100004; rev:1;)"
    assert suricata.next_sid(rules) == 9100005
    assert suricata.next_sid("") == suricata.SID_BASE


def test_build_http_rule():
    r = suricata.build_rule({
        "msg": 'path "traversal"', "proto": "http", "direction": "to_server", "port": 8003,
        "matches": [{"buffer": "http.uri", "value": "/../", "nocase": True}],
    })
    assert not r["errors"], r["errors"]
    assert r["rule"].startswith("alert http any any -> any 8003 (")
    assert 'msg:"path \\"traversal\\""' in r["rule"]
    assert 'http.uri; content:"/../"; nocase' in r["rule"]
    assert "flow:established,to_server" in r["rule"]


def test_hex_content():
    r = suricata.build_rule({"proto": "tcp", "matches": [{"buffer": "payload", "value": "00ff 41\\x42", "hex": True}]})
    assert 'content:"|00 FF 41 42|"' in r["rule"], r
    bad = suricata.build_rule({"proto": "tcp", "matches": [{"buffer": "payload", "value": "abc", "hex": True}]})
    assert bad["errors"]


def test_direction_buffer_mismatch_is_an_error():
    r = suricata.build_rule({"proto": "http", "direction": "to_client",
                             "matches": [{"buffer": "http.uri", "value": "/admin"}]})
    assert any("request buffer" in e for e in r["errors"])


def test_duplicate_sid_rejected():
    r = suricata.build_rule({"sid": 9100001, "matches": [{"buffer": "http.uri", "value": "/admin"}]},
                            existing_rules="alert http any any -> any any (msg:\"x\"; sid:9100001; rev:1;)")
    assert any("already exists" in e for e in r["errors"])


def test_regex_rule_and_bad_regex():
    ok = suricata.build_rule({"matches": [{"buffer": "http.request_body", "mode": "regex", "value": "union\\s+select", "nocase": True}]})
    assert 'pcre:"/union\\s+select/i"' in ok["rule"], ok["rule"]
    bad = suricata.build_rule({"matches": [{"buffer": "http.uri", "mode": "regex", "value": "(unclosed"}]})
    assert bad["errors"]


def test_ctfproxy_filter_is_valid_python_and_inserts():
    f = ctfproxy.build_filter({"name": "sqli login", "target": "param", "param_name": "username",
                               "mode": "contains", "value": "' or 1=1", "nocase": True, "only_method": "post"}, TEMPLATE)
    assert not f["errors"], f["errors"]
    new_src = ctfproxy.insert_method(TEMPLATE, f["code"])
    assert ctfproxy.validate_module(new_src) == []
    assert f["name"] == "blk_sqli_login"
    assert new_src.index("def blk_sqli_login") < new_src.index("def execute")


def test_ctfproxy_value_cannot_inject_code():
    evil = "x'); import os; os.system('id'); ('"
    f = ctfproxy.build_filter({"name": "t", "target": "raw", "value": evil}, TEMPLATE)
    tree = ast.parse("class Module:\n" + f["code"])
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "attr", "") == "system"]
    assert not calls, "user value leaked into code"


def test_ctfproxy_generated_rule_behaves():
    class Msg:
        url = "/login?u=1"; path = "/login"; query_string = "u=1"; method = "POST"
        headers = {"X-Custom-Trigger": "attack123"}; parameters = {"username": "admin' OR 1=1--"}; raw_body = b"username=admin"
    class Stream:
        current_http_message = Msg(); current_message = b"POST /login HTTP/1.1"
    ns = {"HTTPStream": object}
    for spec, expected in [
        ({"target": "param", "param_name": "username", "value": "' or 1=1", "nocase": True}, True),
        ({"target": "header", "header_name": "x-custom-trigger", "value": "attack"}, True),
        ({"target": "path", "value": "/admin"}, False),
        ({"target": "path", "value": "/login", "only_method": "GET"}, False),
        ({"target": "url", "mode": "regex", "value": r"u=\d"}, True),
    ]:
        f = ctfproxy.build_filter({"name": "t", **spec})
        exec("class M:\n" + f["code"], ns)
        assert getattr(ns["M"](), f["name"])(Stream()) is expected, spec


def test_ctfproxy_refuses_to_block_on_identity_headers():
    # User-Agent / X-Forwarded-For: an attacker and the checker bot routinely
    # share these -- blocking on them is the exact mistake the project's own
    # rule-cookbook warns about. Must be refused regardless of position
    # (primary condition or one of the combined "extra" ones), never silently
    # dropped from the rule.
    for spec in [
        {"name": "t", "target": "header", "header_name": "user-agent", "value": "sqlmap"},
        {"name": "t", "target": "header", "header_name": "User-Agent", "value": "sqlmap"},
        {"name": "t", "target": "header", "header_name": "x-forwarded-for", "value": "10.0.0.1"},
        {"name": "t", "target": "path", "value": "/login",
         "extra": [{"target": "header", "header_name": "user-agent", "value": "sqlmap"}]},
    ]:
        f = ctfproxy.build_filter(spec)
        assert f["errors"], spec
        assert any("user-agent" in e.lower() or "x-forwarded-for" in e.lower() for e in f["errors"]), f["errors"]
        assert f["code"] == ""


def test_ctfproxy_combines_extra_conditions_with_and():
    class Msg:
        url = "/upload?x=1"; path = "/upload"; query_string = "x=1"; method = "POST"
        headers = {}; parameters = {}; raw_body = b"<?php system($_GET['c']); ?>"
    class Stream:
        current_http_message = Msg(); current_message = b""
    ns = {"HTTPStream": object}

    # Two conditions ANDed: path contains "/upload" AND body contains "<?php".
    # Neither alone should fire the rule from a message missing the other half.
    f = ctfproxy.build_filter({
        "name": "t", "target": "path", "value": "/upload",
        "extra": [{"target": "body", "value": "<?php"}],
    })
    assert not f["errors"], f["errors"]
    exec("class M:\n" + f["code"], ns)
    assert getattr(ns["M"](), f["name"])(Stream()) is True

    class MsgWrongPath(Msg):
        path = "/other"
    class StreamWrongPath:
        current_http_message = MsgWrongPath(); current_message = b""
    assert getattr(ns["M"](), f["name"])(StreamWrongPath()) is False

    # A bad "extra" condition (missing value) must surface as an error naming
    # which condition it is, same as a bad primary condition would.
    bad = ctfproxy.build_filter({
        "name": "t", "target": "path", "value": "/upload",
        "extra": [{"target": "body", "value": ""}],
    })
    assert bad["errors"]
    assert any("condition 2" in e for e in bad["errors"]), bad["errors"]


def test_ctfproxy_warns_on_too_few_conditions():
    f = ctfproxy.build_filter({"name": "t", "target": "path", "value": "/admin/panel"})
    assert not f["errors"]
    assert any("1 condition" in w for w in f["warnings"]), f["warnings"]

    f3 = ctfproxy.build_filter({
        "name": "t", "target": "path", "value": "/upload",
        "extra": [{"target": "body", "value": "<?php"}, {"target": "method", "value": "POST", "mode": "equals"}],
    })
    assert not f3["errors"]
    assert not any("condition(s) combined" in w for w in f3["warnings"]), f3["warnings"]


def test_ctfproxy_generated_rule_fails_open():
    class Broken:
        current_http_message = object()   # no attributes at all
        current_message = b""
    f = ctfproxy.build_filter({"name": "t", "target": "path", "value": "/admin"})
    ns = {"HTTPStream": object}
    exec("class M:\n" + f["code"], ns)
    assert getattr(ns["M"](), f["name"])(Broken()) is False


def test_validate_module_catches_breakage():
    assert ctfproxy.validate_module("class Module:\n  def x(self\n") != []
    assert "Module.execute is missing" in ctfproxy.validate_module("class Module:\n    def a(self, s):\n        return 1\n")


if __name__ == "__main__":
    fails = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            try:
                fn(); print("PASS", name)
            except Exception as e:
                fails += 1; print("FAIL", name, repr(e))
    sys.exit(1 if fails else 0)
