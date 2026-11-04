"""Shared paths for source runs and PyInstaller builds."""
import sys
from pathlib import Path

SOURCE_DIR = Path(__file__).resolve().parent
APP_DIR = (Path(sys.executable).resolve().parent
           if getattr(sys, 'frozen', False) else SOURCE_DIR)
RESOURCE_DIR = Path(getattr(sys, '_MEIPASS', SOURCE_DIR))

