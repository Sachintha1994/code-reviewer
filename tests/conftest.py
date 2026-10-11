import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
# keep tests away from the real database and the settings saved from the dashboard
os.environ["REVIEWER_DATA_DIR"] = tempfile.mkdtemp(prefix="reviewer-tests-")
