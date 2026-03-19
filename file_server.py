#!/usr/bin/env python3
"""Simple Phase 2 File Server (TCP + JSON protocol)

The file server trusts the token provided by the group server (no verification in Phase 2).

Protocol (newline-delimited JSON objects):
- listFiles: {"op":"listFiles","token":{...}}
- upload: {"op":"upload","token":{...},"groupName":"G","destFile":"name","data":"base64..."}
- download: {"op":"download","token":{...},"sourceFile":"name"}

Responses: {"status":"ok", ...} or {"status":"error","message":"..."}
"""

import base64
import json
import os
import socket
import threading
from typing import Dict, Any, Optional

METADATA_FILE = "fileserver_metadata.json"
STORAGE_DIR = "storage"

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 12346


def load_metadata() -> Dict[str, Any]:
    if os.path.exists(METADATA_FILE):
        with open(METADATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"files": {}}


def save_metadata(md: Dict[str, Any]) -> None:
    with open(METADATA_FILE, "w", encoding="utf-8") as f:
        json.dump(md, f, indent=2)


def send_json(conn: socket.socket, obj: Any) -> None:
    data = json.dumps(obj, separators=(",", ":")) + "\n"
    conn.sendall(data.encode("utf-8"))


def recv_json(conn: socket.socket) -> Optional[Dict[str, Any]]:
    line = b""
    while not line.endswith(b"\n"):
        chunk = conn.recv(4096)
        if not chunk:
            return None
        line += chunk
    try:
        return json.loads(line.decode("utf-8").strip())
    except json.JSONDecodeError:
        return None


def ensure_storage_dir() -> None:
    os.makedirs(STORAGE_DIR, exist_ok=True)


def handle_client(conn: socket.socket, addr, metadata: Dict[str, Any], lock: threading.Lock) -> None:
    try:
        while True:
            req = recv_json(conn)
            if req is None:
                break

            op = req.get("op")
            if not op:
                send_json(conn, {"status": "error", "message": "Missing op"})
                continue

            token = req.get("token") or {}
            user = token.get("userName")
            groups = set(token.get("groups", []))

            if op == "listFiles":
                files = []
                for name, info in metadata.get("files", {}).items():
                    if info.get("group") in groups:
                        files.append(name)
                send_json(conn, {"status": "ok", "files": sorted(files)})

            elif op == "upload":
                group = req.get("groupName")
                dest = req.get("destFile")
                data_b64 = req.get("data")
                if not (group and dest and data_b64):
                    send_json(conn, {"status": "error", "message": "Missing groupName, destFile, or data"})
                    continue
                if group not in groups:
                    send_json(conn, {"status": "error", "message": "Token not in group"})
                    continue
                try:
                    file_bytes = base64.b64decode(data_b64)
                except Exception:
                    send_json(conn, {"status": "error", "message": "Invalid base64 data"})
                    continue
                ensure_storage_dir()
                dest_path = os.path.join(STORAGE_DIR, dest)
                with open(dest_path, "wb") as f:
                    f.write(file_bytes)
                with lock:
                    metadata.setdefault("files", {})[dest] = {"group": group, "uploadedBy": user}
                    save_metadata(metadata)
                send_json(conn, {"status": "ok"})

            elif op == "download":
                source = req.get("sourceFile")
                if not source:
                    send_json(conn, {"status": "error", "message": "Missing sourceFile"})
                    continue
                file_info = metadata.get("files", {}).get(source)
                if not file_info:
                    send_json(conn, {"status": "error", "message": "File not found"})
                    continue
                if file_info.get("group") not in groups:
                    send_json(conn, {"status": "error", "message": "Token not in file group"})
                    continue
                path = os.path.join(STORAGE_DIR, source)
                if not os.path.exists(path):
                    send_json(conn, {"status": "error", "message": "Stored file missing"})
                    continue
                with open(path, "rb") as f:
                    data_b64 = base64.b64encode(f.read()).decode("utf-8")
                send_json(conn, {"status": "ok", "data": data_b64})

            elif op == "disconnect":
                send_json(conn, {"status": "ok"})
                break

            else:
                send_json(conn, {"status": "error", "message": f"Unknown op: {op}"})

    except Exception as e:
        print(f"[FileServer] Error handling {addr}: {e}")
    finally:
        conn.close()


def serve(host: str, port: int) -> None:
    metadata = load_metadata()
    lock = threading.Lock()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)
    print(f"[FileServer] Listening on {host}:{port}")

    try:
        while True:
            conn, addr = sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr, metadata, lock), daemon=True)
            t.start()
    finally:
        sock.close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Phase 2 File Server")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Host to bind")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to bind")
    args = parser.parse_args()

    serve(args.host, args.port)
