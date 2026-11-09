"""Custom runner for uvicorn ensuring compatibility when AppLocker blocks _multiprocessing.pyd."""

import sys
import types

try:
    import _multiprocessing
except ImportError:
    import _socket
    stub = types.ModuleType("_multiprocessing")
    stub.closesocket = _socket.close
    stub.send = lambda *a: None
    stub.recv = lambda *a: None
    stub.flags = {}
    sys.modules["_multiprocessing"] = stub

import uvicorn
from app.main import app

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")

