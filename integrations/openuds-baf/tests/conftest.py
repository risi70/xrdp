"""Install the fake OpenUDS API and import paths for the suite."""

import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
for path in (str(PLUGIN_ROOT), str(PLUGIN_ROOT / 'tests')):
    if path not in sys.path:
        sys.path.insert(0, path)

import udsfakes

udsfakes.install_fake_uds()
