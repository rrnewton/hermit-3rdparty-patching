"""Focused checks for ci/validate-local.sh (the local validate route).

The route claims to mirror .github/workflows/validate.yml step for step.
These tests pin that claim and the regressions a review already caught
once: a dead HERMIT_WRAPPER export with a safehermit claim nothing read,
and a final owned-Nextest call whose required inputs the script never
set. They live in ci/ with the repo's other Python tests: the hosted
workflow's tests/ Python step has no pytest installed on the runner,
so a tests/ placement would break that step instead of running.
ci/validate-local.sh runs this file explicitly.
"""

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "ci" / "validate-local.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "validate.yml"


def script_text() -> str:
    return SCRIPT.read_text()


def test_script_is_executable_and_parses() -> None:
    assert SCRIPT.stat().st_mode & 0o111, "ci/validate-local.sh must be executable"
    result = subprocess.run(
        ["bash", "-n", str(SCRIPT)], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr


def test_no_dead_wrapper_or_unconfigured_nextest() -> None:
    text = script_text()
    assert "HERMIT_WRAPPER" not in text
    assert "DEV_HERMIT" not in text
    assert "EXECUTION_OWNER" not in text
    invocations = [
        line
        for line in text.splitlines()
        if "run-owned-nextest" in line and not line.lstrip().startswith("#")
    ]
    assert invocations == [], f"owned-Nextest must not be invoked: {invocations}"


def test_mirrors_hosted_validate_steps() -> None:
    text = script_text()
    for mirrored in (
        'grep -rq "$HERMIT_PIN" --include=Cargo.toml .',
        'grep -rq "$REVERIE_PIN" --include=Cargo.toml .',
        "cargo test --locked --lib --bins -p hermit-patching-cli -p reverie-e9patch -p reverie-patching-examples",
        "--skip cache_directory_is_private_and_not_a_symlink --skip overlay_",
        "e9patch::tests::cache_directory_is_private_and_not_a_symlink",
        "python3 -m pytest tests/ -x -q",
        "cargo fmt --all -- --check",
        "cargo clippy --locked -p hermit-patching-cli -p reverie-e9patch -p reverie-patching-examples -- -D warnings",
    ):
        assert mirrored in text, f"hosted step not mirrored locally: {mirrored}"


def test_pins_match_hosted_workflow() -> None:
    workflow = WORKFLOW.read_text()
    text = script_text()
    for name in ("HERMIT_PIN", "REVERIE_PIN"):
        hosted = re.search(rf"{name}:\s*([0-9a-f]{{40}})", workflow)
        local = re.search(rf"{name}=\$\{{{name}:-([0-9a-f]{{40}})\}}", text)
        assert hosted and local, f"{name} not found in workflow and script"
        assert hosted.group(1) == local.group(1), f"{name} drifted from hosted"
