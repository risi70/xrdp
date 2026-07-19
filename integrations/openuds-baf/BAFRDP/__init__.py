"""BAF RDP transport plugin for OpenUDS / UDS Enterprise.

Importing the package registers :class:`BAFRDPTransport` with the
OpenUDS module loader. The import is intentionally strict: when the
running server exposes no supported API surface the plugin refuses to
load instead of degrading (fail closed).
"""

from .transport import BAFRDPTransport

__all__ = ["BAFRDPTransport"]
