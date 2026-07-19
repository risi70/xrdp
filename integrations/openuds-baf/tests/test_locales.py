"""Every portal string must be present in every shipped catalog."""

import ast
import re
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
TRANSPORT = PLUGIN_ROOT / "BAFRDP" / "transport.py"
LOCALES = ("en", "de", "fr", "it", "es")

_MSG_RE = re.compile(
    r'^msgid "(?P<msgid>.*)"\nmsgstr "(?P<msgstr>.*)"$', re.MULTILINE
)


def source_msgids() -> set[str]:
    tree = ast.parse(TRANSPORT.read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "_noop"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)):
            found.add(node.args[0].value)
    assert found, "no _noop() strings found in transport.py"
    return found


def catalog_entries(language: str) -> dict[str, str]:
    po = PLUGIN_ROOT / "BAFRDP" / "locale" / language / "LC_MESSAGES" \
        / "django.po"
    text = po.read_text(encoding="utf-8")
    entries = {}
    for match in _MSG_RE.finditer(text):
        msgid = match["msgid"].replace('\\"', '"').replace("\\\\", "\\")
        msgstr = match["msgstr"].replace('\\"', '"').replace("\\\\", "\\")
        if msgid:
            entries[msgid] = msgstr
    return entries


@pytest.mark.parametrize("language", LOCALES)
def test_catalog_covers_every_source_string(language):
    entries = catalog_entries(language)
    missing = source_msgids() - set(entries)
    assert not missing, f"{language} catalog is missing: {sorted(missing)}"
    empty = [msgid for msgid, msgstr in entries.items() if not msgstr]
    assert not empty, f"{language} catalog has empty entries: {empty}"


@pytest.mark.parametrize("language", [l for l in LOCALES if l != "en"])
def test_translations_differ_from_english(language):
    entries = catalog_entries(language)
    identical = [
        msgid for msgid, msgstr in entries.items()
        if msgstr == msgid and not msgid.startswith("Routing token")
        and "SSH" not in msgid and "RDP" not in msgid
    ]
    # A handful of technical terms may match; wholesale identity means
    # the catalog was generated without translations.
    assert len(identical) < 10, f"{language} looks untranslated"
