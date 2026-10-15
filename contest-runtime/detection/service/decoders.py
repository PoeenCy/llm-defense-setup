"""Compatibility import for the shared decoder engine."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from common.flag_decoders import *  # noqa: F401,F403,E402
