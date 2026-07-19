"""Pure-Python client for the XRDP BAF one-time handle service.

Wire-compatible with sesman/libsesman/baf_handle_service.c so an external
broker can register an assertion and obtain a single-use handle without the C
tool. Speaks the SEQPACKET UNIX-socket protocol; use a local socket when
co-located with the VDI, or a forwarded socket (socat/ssh) otherwise.
"""

from __future__ import annotations

import socket
import struct
import time

MAGIC = 0x42414648  # 'BAFH'
VERSION = 1
OP_STORE = 1
OP_RESOLVE = 2
OP_PING = 4

HANDLE_LEN = 65        # BAF_HANDLE_TEXT_LENGTH + 1
TARGET_LEN = 256       # BAF_HANDLE_MAX_TARGET + 1
MAX_ASSERTION = 16384  # BAF_HANDLE_MAX_ASSERTION

# struct message { u32 magic; u16 version, op; u32 status, assertion_length;
#                  i64 expires_at; u32 count; char handle[65], target[256];
#                  u8 assertion[16384]; }  -- padded to an 8-byte multiple.
_FMT = "<IHHIIqI{}s{}s{}s".format(HANDLE_LEN, TARGET_LEN, MAX_ASSERTION)
_PAD = 3               # struct is 16736 bytes; packed fields are 16733
MSG_SIZE = struct.calcsize(_FMT) + _PAD

STATUS = {
    0: "OK", 1: "NOT_FOUND", 2: "EXPIRED", 3: "CONSUMED",
    4: "TARGET_MISMATCH", 5: "BAD_REQUEST", 6: "CAPACITY",
    7: "UNAVAILABLE", 8: "ERROR",
}


class HandleError(RuntimeError):
    pass


def _pack(op, *, assertion=b"", target="", handle="", expires_at=0, count=0):
    if len(assertion) > MAX_ASSERTION:
        raise HandleError("assertion too large")
    if len(target.encode()) > TARGET_LEN - 1:
        raise HandleError("target too long")
    body = struct.pack(
        _FMT, MAGIC, VERSION, op, 0, len(assertion), int(expires_at), count,
        handle.encode(), target.encode(), assertion,
    )
    return body + b"\x00" * _PAD


def _unpack(buf):
    if len(buf) != MSG_SIZE:
        raise HandleError(f"short reply ({len(buf)} != {MSG_SIZE})")
    magic, version, op, status, alen, exp, count, handle, target, assertion = \
        struct.unpack(_FMT, buf[:struct.calcsize(_FMT)])
    if magic != MAGIC or version != VERSION:
        raise HandleError("bad reply magic/version")
    return {
        "op": op, "status": status, "assertion_length": alen,
        "handle": handle.split(b"\x00", 1)[0].decode(),
        "assertion": assertion[:alen],
    }


def _request(socket_path, msg, timeout_ms=2000):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    s.settimeout(timeout_ms / 1000.0)
    try:
        s.connect(socket_path)
        s.send(msg)
        reply = s.recv(MSG_SIZE)
    finally:
        s.close()
    return _unpack(reply)


def ping(socket_path, timeout_ms=2000) -> bool:
    r = _request(socket_path, _pack(OP_PING), timeout_ms)
    return r["status"] == 0


def store(socket_path, assertion: bytes, target: str, ttl_seconds: int = 90,
          timeout_ms: int = 2000) -> str:
    """Register an assertion; return the single-use handle. Fails closed."""
    if not assertion:
        raise HandleError("empty assertion")
    msg = _pack(OP_STORE, assertion=assertion, target=target,
                expires_at=int(time.time()) + ttl_seconds)
    r = _request(socket_path, msg, timeout_ms)
    if r["status"] != 0 or len(r["handle"]) != HANDLE_LEN - 1:
        raise HandleError(
            f"store failed: {STATUS.get(r['status'], r['status'])}")
    return r["handle"]


if __name__ == "__main__":
    import sys
    sock = sys.argv[1] if len(sys.argv) > 1 else "/run/xrdp/baf-handle.sock"
    print("ping:", ping(sock))
