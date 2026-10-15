"""Explicit local-fixture verification for an immutable chain artifact."""
import ipaddress
import subprocess
import sys
import tempfile
import time

from . import contracts
from .repository import Repository


def _loopback(host):
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def verify(db_path, cfg, artifact_id, fixture, target, flag_id=None, expected=None, timeout=15, port=None):
    """Execute only a supported chain against a literal local target.

    This is intentionally a CLI path, never an API/dashboard action.  The
    record binds the outcome to the exact artifact hash.
    """
    if not _loopback(target):
        raise ValueError("verification target must be localhost or a loopback IP")
    repo = Repository.open(db_path, cfg)
    try:
        artifact = repo.artifact_for_verification(artifact_id)
        if artifact is None:
            raise LookupError("unknown script artifact in this game")
        if artifact["kind"] != "chain":
            raise ValueError("only a whole-chain artifact can be marked reproduced")
        if artifact["support"] != contracts.SCRIPT_SUPPORTED:
            raise ValueError("only a supported artifact can be verified; review needs_edit/unsupported first")
        content = bytes(artifact["content"])
        started = time.time()
        with tempfile.NamedTemporaryFile(suffix=".py") as script:
            script.write(content); script.flush()
            command = [sys.executable, script.name, target]
            if flag_id is not None:
                command.append(flag_id)
            if port is not None:
                command += ["--port", str(port)]
            try:
                run = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     timeout=timeout, check=False)
                output = run.stdout + (b"\n" + run.stderr if run.stderr else b"")
                flags = [m.group().decode("utf-8", "replace") for m in cfg.regex.finditer(output)]
                matched = (expected.encode() in output) if expected is not None else bool(flags)
                status = contracts.VERIFY_REPRODUCED if run.returncode == 0 and matched else contracts.VERIFY_FAILED
                error = None if status == contracts.VERIFY_REPRODUCED else f"exit {run.returncode}; expected flag not observed"
            except subprocess.TimeoutExpired as exc:
                output = (exc.stdout or b"") + (exc.stderr or b"")
                flags, status, error = [], contracts.VERIFY_FAILED, f"timeout after {timeout}s"
        finished = time.time()
        recorded_target = target + ((":" + str(port)) if port is not None else "")
        verification_id = repo.record_verification(artifact, fixture, recorded_target, status, flags,
                                                     output.decode("utf-8", "replace"), error,
                                                     started, finished)
        return {"verification_id": verification_id, "artifact_id": artifact_id,
                "artifact_hash": artifact["content_hash"], "fixture": fixture, "target": recorded_target,
                "status": status, "flags": flags, "error": error,
                "output": output.decode("utf-8", "replace")[:4096],
                "started": started, "finished": finished}
    finally:
        repo.close()
