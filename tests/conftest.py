import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

SAMPLE_RUN = ROOT / "data/scubagear_samples/ScubaResults_fa5589b7-d528-4f80.json"
BASELINES = ROOT / "data/baselines/ScubaBaselines.json"
CROSSWALK = ROOT / "data/mappings/scuba-to-nist-sp-800-53-r5-fedramp-high.csv"
MIGRATIONS = ROOT / "data/mappings/scuba-baseline-policy-migrations.csv"


@pytest.fixture(scope="session")
def run():
    from scuba_oscal.parsers.scubagear import parse_run
    return parse_run(SAMPLE_RUN)


@pytest.fixture(scope="session")
def baselines():
    from scuba_oscal.parsers.baselines import parse_baselines
    return parse_baselines(BASELINES)


@pytest.fixture(scope="session")
def index():
    from scuba_oscal.parsers.mappings import MappingIndex
    return MappingIndex(CROSSWALK, MIGRATIONS)
