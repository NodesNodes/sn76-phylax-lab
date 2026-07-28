"""Malformed dispatch and pathological input. Anything that raises here loses a
repetition in the jail; anything slow here risks the CPU budget."""
import sys, time, json, tempfile, pathlib
sys.path.insert(0, "/root/labs/phylax-subnet")
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "agent"))
from phylax_agent import agent_main
from phylax.analysis import proof, tracks

probe = proof.derive_probe("ab" * 32)
GOOD = probe.as_inputs()

art = pathlib.Path(str(pathlib.Path(__file__).resolve().parents[1]) + "/corpus/packages/known-bad/acme-core")

CONTEXTS = {
    "observed=str":            {"observed": "nope"},
    "observed=list":           {"observed": []},
    "capabilities=str":        {"observed": {"capabilities": "READ_FILE"}},
    "capabilities=[None]":     {"observed": {"capabilities": [None, 3, {"x": 1}]}},
    "phases=list":             {"observed": {"phases": []}},
    "phases val=str":          {"observed": {"phases": {"install_time": "boom"}}},
    "phase caps=str":          {"observed": {"phases": {"install_time": {"capabilities": "X"}}}},
    "tool_surface=str":        {"observed": {"tool_surface": "x"}},
    "tool_surface=[str]":      {"observed": {"tool_surface": ["x", None]}},
    "tool schema=str":         {"observed": {"tool_surface": [{"name": "t", "inputSchema": "s"}]}},
    "tool name=None":          {"observed": {"tool_surface": [{"name": None}]}},
    "probe=list":              {"probe": []},
    "probe=None":              {"probe": None},
    "probe vals=int":          {"probe": {"file_path": 1, "dns_host": 2, "process_echo": 3}},
    "track=None":              {"track": None},
    "track=weird":             {"track": "no_such_track"},
    "artifact_dir=missing":    {"artifact_dir": "/does/not/exist"},
    "artifact_dir=file":       {"artifact_dir": "/etc/hostname"},
    "artifact_dir=None":       {"artifact_dir": None},
    "context=None":            None,
    "context=list":            [],
    "deep schema":             {"observed": {"tool_surface": [
                                   {"name": "t", "inputSchema": json.loads(
                                       '{"a":' * 60 + '1' + '}' * 60)}]}},
}

fails = []
for track in ("skills", "mcp_servers", "packages", "repositories"):
    for name, extra in CONTEXTS.items():
        if isinstance(extra, dict):
            ctx = {"track": track, "artifact_dir": str(art), "probe": GOOD}
            ctx.update(extra)
        else:
            ctx = extra
        try:
            t0 = time.perf_counter()
            r = agent_main(ctx)
            dt = time.perf_counter() - t0
            assert isinstance(r, dict), "not a dict"
            assert str(r["verdict"]["decision"]) in ("ALLOW", "WARN", "BLOCK"), r["verdict"]
            assert isinstance(r["evidence"], dict) and isinstance(r["findings"], list)
            if r["evidence"].get("error"):
                fails.append(f"{track:12} {name:22} DEGRADED ({r['evidence']['error']})")
            elif dt > 1.0:
                fails.append(f"{track:12} {name:22} SLOW {dt:.2f}s")
        except Exception as e:
            fails.append(f"{track:12} {name:22} RAISED {type(e).__name__}: {e}")

print("\n".join(fails) if fails else "no crashes, no degraded fallbacks, none slow")
print(f"\n{len(CONTEXTS) * 4} dispatches, {len(fails)} problems")
