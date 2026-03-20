#!/usr/bin/env python3
"""Simple Phase 2 Group Server (TCP + JSON protocol)

Protocol (newline-delimited JSON objects):
- Request: {"op": "getToken", "userName": "alice"}
- Response: {"status": "ok", "token": {...}}

State is persisted to disk in groupserver_state.json so the server can be restarted.
"""

import json
import os
import socket
import threading
from typing import Dict, Any, Optional

STATE_FILE = "groupserver_state.json"

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 12345


def load_state() -> Dict[str, Any]:
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)

    return {
        "users": ["admin"],
        "groups": {
            "ADMIN": {
                "owner": "admin",
                "members": ["admin"],
            }
        },
    }


def save_state(state: Dict[str, Any]) -> None:
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def make_token(user: str, state: Dict[str, Any]) -> Dict[str, Any]:
    user_groups = [g for g, info in state["groups"].items() if user in info["members"]]
    return {"userName": user, "groups": sorted(user_groups)}


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


def handle_client(conn: socket.socket, addr, state: Dict[str, Any], lock: threading.Lock) -> None:
    try:
        while True:
            req = recv_json(conn)
            if req is None:
                break

            op = req.get("op")
            if not op:
                send_json(conn, {"status": "error", "message": "Missing op"})
                continue

            if op == "getToken":
                user = req.get("userName")
                if not user:
                    send_json(conn, {"status": "error", "message": "Missing userName"})
                    continue
                with lock:
                    if user not in state["users"]:
                        state["users"].append(user)
                        save_state(state)
                    token = make_token(user, state)
                send_json(conn, {"status": "ok", "token": token})

            elif op == "createUser":
                token = req.get("token")
                new_user = req.get("userName")
                if not token or not new_user:
                    send_json(conn, {"status": "error", "message": "Missing token or userName"})
                    continue
                caller = token.get("userName")
                caller_groups = token.get("groups", [])
                if "ADMIN" not in caller_groups:
                    send_json(conn, {"status": "error", "message": "Must be ADMIN to create user"})
                    continue
                with lock:
                    if new_user in state["users"]:
                        send_json(conn, {"status": "error", "message": "User already exists"})
                        continue
                    state["users"].append(new_user)
                    save_state(state)
                send_json(conn, {"status": "ok"})

            elif op == "createGroup":
                token = req.get("token")
                group = req.get("groupName")
                if not token or not group:
                    send_json(conn, {"status": "error", "message": "Missing token or groupName"})
                    continue
                caller = token.get("userName")
                if group in state["groups"]:
                    send_json(conn, {"status": "error", "message": "Group already exists"})
                    continue
                with lock:
                    state["groups"][group] = {"owner": caller, "members": [caller]}
                    save_state(state)
                send_json(conn, {"status": "ok"})

            elif op == "addUserToGroup":
                token = req.get("token")
                group = req.get("groupName")
                user = req.get("userName")
                if not token or not group or not user:
                    send_json(conn, {"status": "error", "message": "Missing token, groupName, or userName"})
                    continue
                caller = token.get("userName")
                group_info = state["groups"].get(group)
                if not group_info:
                    send_json(conn, {"status": "error", "message": "Unknown group"})
                    continue
                if group_info["owner"] != caller:
                    send_json(conn, {"status": "error", "message": "Only the group owner can add users"})
                    continue
                with lock:
                    if user not in state["users"]:
                        state["users"].append(user)
                    if user not in group_info["members"]:
                        group_info["members"].append(user)
                    save_state(state)
                send_json(conn, {"status": "ok"})

            elif op == "listMembers":
                token = req.get("token")
                group = req.get("groupName")
                if not token or not group:
                    send_json(conn, {"status": "error", "message": "Missing token or groupName"})
                    continue
                caller = token.get("userName")
                group_info = state["groups"].get(group)
                if not group_info:
                    send_json(conn, {"status": "error", "message": "Unknown group"})
                    continue
                if group_info["owner"] != caller:
                    send_json(conn, {"status": "error", "message": "Only the group owner can list members"})
                    continue
                send_json(conn, {"status": "ok", "members": sorted(group_info["members"])})

            elif op == "disconnect":
                send_json(conn, {"status": "ok"})
                break

            else:
                send_json(conn, {"status": "error", "message": f"Unknown op: {op}"})

    except Exception as e:
        print(f"[GroupServer] Error handling {addr}: {e}")
    finally:
        conn.close()


def serve(host: str, port: int) -> None:
    state = load_state()
    lock = threading.Lock()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)
    print(f"[GroupServer] Listening on {host}:{port}")

    try:
        while True:
            conn, addr = sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr, state, lock), daemon=True)
            t.start()
    finally:
        sock.close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Phase 2 Group Server")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Host to bind")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to bind")
    args = parser.parse_args()

    serve(args.host, args.port)
