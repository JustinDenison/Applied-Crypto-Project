#!/usr/bin/env python3
"""Phase 2 Client CLI for Group Server + File Server.

Usage example:
  python p2client.py --group-host localhost --group-port 12345 --file-host localhost --file-port 12346

Once running, follow the interactive prompt to call group/file operations.
"""

import argparse
import base64
import json
import socket
from typing import Any, Dict, Optional


def send_request(sock: socket.socket, req: Dict[str, Any]) -> Dict[str, Any]:
    data = json.dumps(req, separators=(",", ":")) + "\n"
    sock.sendall(data.encode("utf-8"))
    # Read a single line response
    line = b""
    while not line.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("Connection closed")
        line += chunk
    return json.loads(line.decode("utf-8").strip())


class ServerConnection:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None

    def connect(self) -> None:
        if self.sock:
            return
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))

    def close(self) -> None:
        if not self.sock:
            return
        try:
            send_request(self.sock, {"op": "disconnect"})
        except Exception:
            pass
        self.sock.close()
        self.sock = None

    def call(self, req: Dict[str, Any]) -> Dict[str, Any]:
        if not self.sock:
            self.connect()
        assert self.sock is not None
        return send_request(self.sock, req)


def interactive(group_conn: ServerConnection, file_conn: ServerConnection) -> None:
    token: Optional[Dict[str, Any]] = None

    def require_token() -> Dict[str, Any]:
        nonlocal token
        if token is None:
            raise RuntimeError("No token obtained; run getToken first")
        return token

    print("Phase 2 client. Type 'help' for commands.")
    while True:
        try:
            line = input("p2> ").strip()
        except EOFError:
            print()
            break
        if not line:
            continue
        parts = line.split()
        cmd = parts[0].lower()

        try:
            if cmd in ("quit", "exit"):
                break

            elif cmd == "help":
                print("Commands:")
                print("  getToken <user>                      - obtain a token from the group server")
                print("  createUser <user>                    - (ADMIN only) create a new user")
                print("  createGroup <group>                  - create a group (you become owner)")
                print("  addUserToGroup <user> <group>        - (owner only) add a user to a group")
                print("  listMembers <group>                  - (owner only) list members")
                print("  listFiles                            - list files you can see")
                print("  upload <local> <remote> <group>      - upload a file into a group")
                print("  download <remote> <local>            - download a file you have access to")
                print("  token                                - print current token")
                print("  help                                 - show this message")
                print("  exit                                 - quit")

            elif cmd == "gettoken":
                if len(parts) != 2:
                    print("Usage: getToken <user>")
                    continue
                user = parts[1]
                resp = group_conn.call({"op": "getToken", "userName": user})
                if resp.get("status") == "ok":
                    token = resp.get("token")
                    print("Got token for", user)
                else:
                    print("Error:", resp.get("message"))

            elif cmd == "createuser":
                if len(parts) != 2:
                    print("Usage: createUser <user>")
                    continue
                require_token()
                resp = group_conn.call({"op": "createUser", "userName": parts[1], "token": token})
                print(resp.get("status"), resp.get("message", ""))

            elif cmd == "creategroup":
                if len(parts) != 2:
                    print("Usage: createGroup <group>")
                    continue
                require_token()
                resp = group_conn.call({"op": "createGroup", "groupName": parts[1], "token": token})
                print(resp.get("status"), resp.get("message", ""))

            elif cmd == "addusertogroup":
                if len(parts) != 3:
                    print("Usage: addUserToGroup <user> <group>")
                    continue
                require_token()
                resp = group_conn.call({
                    "op": "addUserToGroup",
                    "userName": parts[1],
                    "groupName": parts[2],
                    "token": token,
                })
                print(resp.get("status"), resp.get("message", ""))

            elif cmd == "listmembers":
                if len(parts) != 2:
                    print("Usage: listMembers <group>")
                    continue
                require_token()
                resp = group_conn.call({"op": "listMembers", "groupName": parts[1], "token": token})
                if resp.get("status") == "ok":
                    print("Members:", ", ".join(resp.get("members", [])))
                else:
                    print("Error:", resp.get("message"))

            elif cmd == "listfiles":
                require_token()
                resp = file_conn.call({"op": "listFiles", "token": token})
                if resp.get("status") == "ok":
                    print("Files:")
                    for f in resp.get("files", []):
                        print(" ", f)
                else:
                    print("Error:", resp.get("message"))

            elif cmd == "upload":
                if len(parts) != 4:
                    print("Usage: upload <local> <remote> <group>")
                    continue
                require_token()
                local = parts[1]
                remote = parts[2]
                group = parts[3]
                with open(local, "rb") as f:
                    data_b64 = base64.b64encode(f.read()).decode("utf-8")
                resp = file_conn.call({
                    "op": "upload",
                    "token": token,
                    "groupName": group,
                    "destFile": remote,
                    "data": data_b64,
                })
                print(resp.get("status"), resp.get("message", ""))

            elif cmd == "download":
                if len(parts) != 3:
                    print("Usage: download <remote> <local>")
                    continue
                require_token()
                source = parts[1]
                local = parts[2]
                resp = file_conn.call({"op": "download", "token": token, "sourceFile": source})
                if resp.get("status") != "ok":
                    print("Error:", resp.get("message"))
                    continue
                data_b64 = resp.get("data")
                if data_b64 is None:
                    print("No data in response")
                    continue
                with open(local, "wb") as f:
                    f.write(base64.b64decode(data_b64))
                print("Wrote", local)

            elif cmd == "token":
                if token is None:
                    print("No token yet (run getToken)")
                else:
                    print(json.dumps(token, indent=2))

            else:
                print("Unknown command: ", cmd)

        except Exception as e:
            print("Error:", e)

    group_conn.close()
    file_conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phase 2 client for group+file servers")
    parser.add_argument("--group-host", default="localhost")
    parser.add_argument("--group-port", type=int, default=12345)
    parser.add_argument("--file-host", default="localhost")
    parser.add_argument("--file-port", type=int, default=12346)
    args = parser.parse_args()

    group_conn = ServerConnection(args.group_host, args.group_port)
    file_conn = ServerConnection(args.file_host, args.file_port)

    interactive(group_conn, file_conn)
