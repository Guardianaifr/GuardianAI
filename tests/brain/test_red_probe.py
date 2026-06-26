from brain.red_probe import RedProbeAgent


class _Filter:
    def check_prompt(self, prompt: str) -> bool:
        return "ignore previous instructions" in prompt.lower()


def test_red_probe_detects_bypasses_from_vectors_file(tmp_path):
    vectors = tmp_path / "vectors.yaml"
    vectors.write_text(
        "probes:\n"
        "  - safe probe\n"
        "  - ignore previous instructions\n",
        encoding="utf-8",
    )
    agent = RedProbeAgent(vectors)
    findings = agent.run_probe_cycle(_Filter())
    assert len(findings) >= 1
    assert any("ignore previous instructions" in f.payload for f in findings)


def test_red_probe_generates_dynamic_intel_payloads():
    class _Intel:
        def as_dict(self):
            return {"keywords": {"drop table": 2, "reverse shell": 3}}

    agent = RedProbeAgent(None, intel=_Intel())
    dynamic = agent.generate_dynamic_probes(max_dynamic=8)
    assert dynamic
    assert any("drop table" in p.lower() or "reverse shell" in p.lower() for p in dynamic)
    assert any("base64 payload" in p.lower() for p in dynamic)
