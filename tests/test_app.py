"""Smoke tests for the Streamlit app.

The app is where most of the project's claims are actually *shown*, so a view
that raises -- or that asserts something the artifacts do not support -- is a
demo-day failure. These run the real script through Streamlit's AppTest
harness, which executes every view exactly as a browser would.

Skipped when the `app` extra is not installed (CI's `dev` extra does not
include Streamlit), so this never blocks the deterministic core.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("streamlit", reason="requires the [app] extra")

from streamlit.testing.v1 import AppTest  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "src/scuba_oscal/app/main.py"
VIEWS = ["start", "posture", "fix", "ask", "drift", "docs", "impact"]


@pytest.fixture(scope="module", autouse=True)
def generated():
    if not (ROOT / "data/oscal_out/scuba-m365-catalog.json").exists():
        subprocess.run([sys.executable, str(ROOT / "scripts/generate.py")], check=True)


def _run(view: str) -> AppTest:
    at = AppTest.from_file(str(APP), default_timeout=180)
    at.run()
    assert not at.exception, f"app failed before any view was chosen: {at.exception}"
    at.radio[0].set_value(view).run()
    return at


@pytest.mark.parametrize("view", VIEWS)
def test_view_renders_without_error(view):
    at = _run(view)
    assert not at.exception, f"view '{view}' raised: {[e.value for e in at.exception]}"


def test_evidence_view_does_not_overstate_validation():
    """The validator claim must be earned, not printed.

    This page used to assert "All N documents pass NIST's official OSCAL
    validator" from a file count, while never invoking a validator and while
    one document is in fact schema-only. It must now say which tier ran.
    """
    at = _run("docs")
    banners = " ".join(m.value for m in at.success)
    assert "JSON Schema" in banners, "the page must name the tier it actually ran"
    assert "official OSCAL validator" not in banners

    captions = " ".join(c.value for c in at.caption)
    assert "mapping-collection" in captions, "the unsupported model must be disclosed"


def test_posture_and_exemption_rates_are_consistent():
    """The headline rate and the exemption panel must not contradict each other.

    Both describe the same tenant over the same denominator, so a reader seeing
    two different "real" percentages on one page is being told the pipeline
    disagrees with itself.
    """
    at = _run("posture")
    assert not at.exception
    blocks = [m.value for m in at.markdown]

    headline = next(b for b in blocks if "Overall score" in b)
    assert "68.7%" in headline

    # The "over all assessed" card must agree with the headline. The pre-fix
    # code put 66.3% here by scoring passing-but-omitted policies as unmet,
    # so the same page showed two different "real" rates.
    card = next(b for b in blocks if "Over all assessed" in b)
    assert "68.7%" in card
    assert "66.3%" not in card

    # 66.3% is still reported, but only as an explicitly conservative bound.
    bound = next(b for b in blocks if "66.3%" in b)
    assert "bound" in bound


def test_ask_view_degrades_gracefully_without_foundry():
    """Missing Foundry setup must explain itself, not traceback.

    The import of the Foundry SDK used to sit outside the try block, so
    following the README's own quickstart -- which installs [app,dev] and not
    [ai] -- answered the first click with a raw Python traceback. That is a
    demo-day failure in the one view that demonstrates the mandatory
    technology.

    Passes in both directions: with the SDK absent it must name the extra to
    install; with the SDK present but unconfigured it must name the missing
    setting. Never an unhandled exception.
    """
    at = _run("ask")
    button = next(b for b in at.button if "Ask" in b.label)
    button.click().run()

    assert not at.exception, (
        "clicking Ask without Foundry configured raised: "
        f"{[e.value for e in at.exception]}"
    )

    said = " ".join(m.value for m in at.error) + " " + " ".join(m.value for m in at.info)
    assert '.[ai]' in said or "FOUNDRY_PROJECT_ENDPOINT" in said, (
        f"expected actionable setup guidance, got: {said[:200]}"
    )
