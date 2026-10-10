import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

collect_ignore = ["fixtures"]
FIXTURE = ROOT / "tests" / "fixtures" / "sample_project"
