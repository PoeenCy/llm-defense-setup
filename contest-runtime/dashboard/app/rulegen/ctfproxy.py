"""Generate ctf_proxy filter methods (Python) from a structured description,
and splice them into an existing <service>_in.py.

ctf_proxy calls every public method of `class Module` on each HTTP message and
drops the connection when one returns True (see the upstream template's
execute()). User-supplied values are embedded with repr(), never pasted as
code, so a value can't inject Python into the filter file.
"""
import ast
import re

TARGETS = {
    "url":          "str(message.url or '')",
    "path":         "str(message.path or '')",
    "query_string": "str(message.query_string or '')",
    "method":       "str(message.method or '')",
    "body":         "bytes(message.raw_body or b'').decode('latin-1', 'replace')",
    "raw":          "bytes(stream.current_message or b'').decode('latin-1', 'replace')",
}

# Headers that an attacker and the organizer's checker bot routinely share
# (same browser/library User-Agent, same NAT'd source IP behind a proxy) --
# blocking on these is the exact mistake the project's own rule-cookbook
# warns about ("UA/IP chỉ dùng để CẢNH BÁO, tuyệt đối không để CHẶN"). There
# is no "ip" target in TARGETS at all (structurally impossible to block by
# IP through ctf_proxy), so this is the other half of that same rule: block
# it here too, not just document it.
IDENTITY_HEADERS = {"user-agent", "x-forwarded-for"}


def safe_name(name: str) -> str:
    n = re.sub(r"[^a-z0-9_]+", "_", (name or "").lower()).strip("_")
    if not n:
        n = "rule"
    if n[0].isdigit():
        n = "r_" + n
    return "blk_" + n if not n.startswith("blk_") else n


def existing_methods(source: str) -> set[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set(re.findall(r"^\s+def (\w+)\(", source, re.M))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "Module":
            names |= {f.name for f in node.body if isinstance(f, ast.FunctionDef)}
    return names


def _data_expr(cond: dict) -> str:
    target = cond.get("target", "raw")
    if target == "param":
        return f"str((message.parameters or {{}}).get({cond.get('param_name', '')!r}, ''))"
    if target == "header":
        hname = (cond.get("header_name") or "").lower()
        return f"str({{str(k).lower(): v for k, v in (message.headers or {{}}).items()}}.get({hname!r}, ''))"
    return TARGETS[target]


def _validate_condition(cond: dict, stream_type: str, label: str, errors: list[str]) -> None:
    target = cond.get("target", "raw")
    if stream_type == "tcp":
        if target != "raw":
            errors.append(f"{label}: this service is not HTTP-parsed (raw TCP) -- only target 'raw' is available, got {target!r}")
    elif target not in TARGETS and target not in ("param", "header"):
        errors.append(f"{label}: unknown target {target!r}")
    if target == "param" and not cond.get("param_name"):
        errors.append(f"{label}: target 'param' needs param_name")
    if target == "header":
        hname = (cond.get("header_name") or "").strip().lower()
        if not hname:
            errors.append(f"{label}: target 'header' needs header_name")
        elif hname in IDENTITY_HEADERS:
            errors.append(
                f"{label}: cannot BLOCK on header {hname!r} -- an attacker and the checker bot "
                "routinely share it (same User-Agent, or the same NAT'd IP via X-Forwarded-For). "
                "Use Suricata to ALERT on it instead; ctf_proxy refuses to block on it."
            )
    value = cond.get("value") or ""
    if not value:
        errors.append(f"{label}: value is required")
    mode = cond.get("mode", "contains")
    if mode == "regex":
        try:
            re.compile(value)
        except re.error as e:
            errors.append(f"{label}: invalid regex: {e}")
    elif mode not in ("contains", "equals"):
        errors.append(f"{label}: unknown mode {mode!r}")


def build_filter(spec: dict, source: str = "", stream_type: str = "http") -> dict:
    """spec: name, description, target(url|path|query_string|method|body|raw|param|header),
    param_name, header_name, mode(contains|equals|regex), value, nocase -- the
    PRIMARY condition -- plus only_method, only_path_contains (narrow the
    whole rule, HTTP-only), and an optional `extra`: a list of further
    {target, mode, value, nocase, param_name, header_name} dicts, each
    validated the same way as the primary one and ANDed together with it.
    Combining conditions (e.g. a specific path AND a specific body payload)
    is what actually keeps a BLOCKING rule narrow enough not to also catch
    the checker -- a single short/generic condition is the common way a
    block rule costs SLA. Returns {code, name, errors, warnings}.

    stream_type: "http" (default) for a service ctf_proxy parses as HTTP, or
    "tcp" for a raw/non-HTTP service -- there is no parsed message to pull
    url/path/method/param/header from, only the raw bytes of the current
    message, so "tcp" only accepts target="raw" on every condition and
    ignores only_method/only_path_contains (those need HTTP parsing too)."""
    errors: list[str] = []
    warnings: list[str] = []
    # Only copy keys the caller actually set -- a dict comprehension over the
    # full key list would store an explicit `None` for anything missing, and
    # `cond.get("mode", "contains")` does NOT fall back to its default for a
    # key that's present-but-None, only for a key that's absent entirely.
    primary = {k: spec[k] for k in ("target", "mode", "value", "nocase", "param_name", "header_name")
               if spec.get(k) is not None}
    conditions = [primary] + list(spec.get("extra") or [])

    for i, cond in enumerate(conditions):
        label = "condition 1 (primary)" if i == 0 else f"condition {i + 1}"
        _validate_condition(cond, stream_type, label, errors)

    value0 = primary.get("value") or ""
    name = safe_name(spec.get("name") or value0[:24])
    taken = existing_methods(source)
    base, n = name, 2
    while name in taken:
        name, n = f"{base}_{n}", n + 1

    short = sum(1 for c in conditions if len(c.get("value") or "") < 4 and c.get("mode", "contains") != "regex")
    if short:
        warnings.append(f"{short} condition(s) have a very short value — likely to block legitimate (checker) traffic too")
    if len(conditions) < 3:
        warnings.append(
            f"only {len(conditions)} condition(s) combined — for a rule that actually BLOCKS, consider "
            "adding more (e.g. path + parameter + body content together) to reduce the chance of also "
            "matching the checker, especially when there's no time left to Test on recent traffic carefully"
        )

    if errors:
        return {"code": "", "name": name, "errors": errors, "warnings": warnings}

    desc = (spec.get("description") or f"block on {len(conditions)} combined condition(s)").replace('"""', "'''")
    narrow_conds = []
    if stream_type != "tcp":
        if spec.get("only_method"):
            narrow_conds.append(f"str(message.method or '').upper() == {spec['only_method'].upper()!r}")
        if spec.get("only_path_contains"):
            narrow_conds.append(f"{spec['only_path_contains']!r} in str(message.path or '')")

    data_lines, test_exprs = [], []
    for i, cond in enumerate(conditions):
        mode = cond.get("mode", "contains")
        value = cond.get("value") or ""
        nocase = bool(cond.get("nocase"))
        data_expr = TARGETS["raw"] if stream_type == "tcp" else _data_expr(cond)
        var = f"data{i}"
        data_lines.append(f"            {var} = {data_expr}")
        if mode == "regex":
            flags = "re.IGNORECASE" if nocase else "0"
            test_exprs.append(f"re.search({value!r}, {var}, {flags}) is not None")
        elif mode == "equals":
            test_exprs.append(f"{var}.lower() == {value.lower()!r}" if nocase else f"{var} == {value!r}")
        else:
            test_exprs.append(f"{value.lower()!r} in {var}.lower()" if nocase else f"{value!r} in {var}")

    stream_hint = "TCPStream" if stream_type == "tcp" else "HTTPStream"
    lines = [
        f"    def {name}(self, stream: {stream_hint}):",
        f'        """{desc} [generated by dashboard rule builder]"""',
    ]
    # Fail OPEN: upstream execute() only catches IndexError, so any other
    # exception from a generated rule must never escape and disturb traffic.
    lines.append("        try:")
    if any(c.get("mode", "contains") == "regex" for c in conditions):
        lines.append("            import re")
    if stream_type != "tcp":
        lines.append("            message = stream.current_http_message")
        lines.append("            if message is None:")
        lines.append("                return False")
    if narrow_conds:
        lines.append(f"            if not ({' and '.join(narrow_conds)}):")
        lines.append("                return False")
    lines.extend(data_lines)
    lines.append(f"            return {' and '.join(test_exprs)}")
    lines.append("        except Exception:")
    lines.append("            return False")
    code = "\n".join(lines) + "\n"
    return {"code": code, "name": name, "errors": [], "warnings": warnings}


def insert_method(source: str, method_code: str) -> str:
    """Insert before `def execute` inside class Module (keeps execute last, the
    way the upstream template is laid out). Raises ValueError if the file
    doesn't look like a ctf_proxy filter module."""
    m = re.search(r"^    def execute\(self", source, re.M)
    if not m or "class Module" not in source:
        raise ValueError("this file doesn't look like a ctf_proxy filter module (no class Module / def execute)")
    return source[:m.start()] + method_code + "\n" + source[m.start():]


def validate_module(source: str) -> list[str]:
    """Static checks that catch a broken filter before it is uploaded: it must
    parse, still define Module.execute, and every rule method must take
    (self, stream)."""
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return [f"Python syntax error line {e.lineno}: {e.msg}"]
    mods = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Module"]
    if not mods:
        return ["class Module is missing"]
    funcs = {f.name: f for f in mods[0].body if isinstance(f, ast.FunctionDef)}
    errs = []
    if "execute" not in funcs:
        errs.append("Module.execute is missing")
    for fname, f in funcs.items():
        if fname.startswith("__"):
            continue
        if len(f.args.args) != 2:
            errs.append(f"method {fname} must take exactly (self, stream)")
    return errs
