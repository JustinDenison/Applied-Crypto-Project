#!/usr/bin/env python3
"""Phase 3 Client - Cryptographically Hardened (ECDHE + AES-256-GCM + Ed25519)"""

import argparse
import base64
import json
import socket
import secrets
import time
from typing import Any, Dict, Optional
from base64 import b64encode, b64decode

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def encrypt_message(plaintext_dict: Dict[str, Any], session_key: bytes) -> str:
    """Encrypt message using AES-256-GCM"""
    plaintext = json.dumps(plaintext_dict, separators=(",", ":")).encode("utf-8")
    nonce = secrets.token_bytes(12)
    cipher = AESGCM(session_key)
    ciphertext = cipher.encrypt(nonce, plaintext, None)
    return b64encode(nonce + ciphertext).decode("utf-8")


def decrypt_message(encrypted_b64: str, session_key: bytes) -> Dict[str, Any]:
    """Decrypt message using AES-256-GCM"""
    encrypted_bytes = b64decode(encrypted_b64)
    nonce = encrypted_bytes[:12]
    ciphertext = encrypted_bytes[12:]
    cipher = AESGCM(session_key)
    plaintext = cipher.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))


def client_derive_session_key(my_private_b64: str, server_public_b64: str) -> bytes:
    """Derive session key from server's public key"""
    my_private_bytes = b64decode(my_private_b64)
    my_private = x25519.X25519PrivateKey.from_private_bytes(my_private_bytes)
    
    server_public_bytes = b64decode(server_public_b64)
    server_public = x25519.X25519PublicKey.from_public_bytes(server_public_bytes)
    
    shared_secret = my_private.exchange(server_public)
    
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=b"session_key")
    return hkdf.derive(shared_secret)


class ServerConnection:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
        self.session_key: Optional[bytes] = None
        self.my_ephemeral_private_b64: Optional[str] = None

    def connect(self) -> None:
        if self.sock:
            return
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        self._ecdhe_handshake()

    def _ecdhe_handshake(self) -> None:
        """Perform ECDHE key exchange"""
        client_private = x25519.X25519PrivateKey.generate()
        client_public = client_private.public_key()
        
        client_public_bytes = client_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        client_public_b64 = b64encode(client_public_bytes).decode()
        
        # Send client public key (unencrypted)
        msg = json.dumps({"client_ephemeral_public": client_public_b64}, separators=(",", ":")) + "\n"
        self.sock.sendall(msg.encode("utf-8"))
        
        # Receive server public key
        line = b""
        while not line.endswith(b"\n"):
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("Connection closed during handshake")
            line += chunk
        
        server_response = json.loads(line.decode("utf-8").strip())
        server_public_b64 = server_response.get("server_ephemeral_public")
        if not server_public_b64:
            raise RuntimeError("No server ephemeral public key received")
        
        # Store private key and derive session key
        self.my_ephemeral_private_b64 = b64encode(
            client_private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
        ).decode()
        
        self.session_key = client_derive_session_key(self.my_ephemeral_private_b64, server_public_b64)
        print(f"[CLIENT] Connected to {self.host}:{self.port}, session key established")

    def close(self) -> None:
        if not self.sock:
            return
        try:
            self.call({"op": "disconnect"})
        except Exception:
            pass
        self.sock.close()
        self.sock = None

    def call(self, req: Dict[str, Any]) -> Dict[str, Any]:
        if not self.sock:
            self.connect()
        
        # Add nonce and timestamp
        req["nonce"] = b64encode(secrets.token_bytes(16)).decode()
        req["timestamp"] = int(time.time())
        
        # Encrypt and send
        encrypted_b64 = encrypt_message(req, self.session_key)
        wrapper = {"encrypted": encrypted_b64}
        data = json.dumps(wrapper, separators=(",", ":")) + "\n"
        self.sock.sendall(data.encode("utf-8"))
        
        # Receive encrypted response
        line = b""
        while not line.endswith(b"\n"):
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("Connection closed")
            line += chunk
        
        wrapper_resp = json.loads(line.decode("utf-8").strip())
        encrypted_resp_b64 = wrapper_resp.get("encrypted")
        if not encrypted_resp_b64:
            raise RuntimeError("No encrypted response")
        
        return decrypt_message(encrypted_resp_b64, self.session_key)


def interactive(group_conn: ServerConnection, file_conn: ServerConnection) -> None:
    token: Optional[Dict[str, Any]] = None
    token_signature: Optional[str] = None

    def require_token() -> Dict[str, Any]:
        nonlocal token
        if token is None:
            raise RuntimeError("No token obtained; run getToken first")
        return token

    print("Phase 3 client (cryptographically hardened). Type 'help' for commands.")
    while True:
        try:
            line = input("p3> ").strip()
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
                print("  getToken <user> <password>           - authenticate and get token")
                print("  createUser <user> [password]         - (ADMIN only) create a new user")
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
                if len(parts) < 3:
                    print("Usage: getToken <user> <password>")
                    continue
                user = parts[1]
                password = parts[2]
                resp = group_conn.call({"op": "getToken", "userName": user, "password": password})
                if resp.get("status") == "ok":
                    token = resp.get("token")
                    token_signature = resp.get("token_signature")
                    print(f"✓ Got token for {user}")
                else:
                    print("✗ Error:", resp.get("message"))

            elif cmd == "createuser":
                if len(parts) < 2:
                    print("Usage: createUser <user> [password]")
                    continue
                require_token()
                new_user = parts[1]
                password = parts[2] if len(parts) > 2 else "changeme"
                resp = group_conn.call({
                    "op": "createUser",
                    "userName": new_user,
                    "password": password,
                    "token": token
                })
                print(resp.get("status"), resp.get("message", ""))

            elif cmd == "creategroup":
                if len(parts) < 2:
                    print("Usage: createGroup <group>")
                    continue
                require_token()
                resp = group_conn.call({
                    "op": "createGroup",
                    "groupName": parts[1],
                    "token": token
                })
                print(resp.get("status"), resp.get("message", ""))

            elif cmd == "addusertogroup":
                if len(parts) < 3:
                    print("Usage: addUserToGroup <user> <group>")
                    continue
                require_token()
                resp = group_conn.call({
                    "op": "addUserToGroup",
                    "userName": parts[1],
                    "groupName": parts[2],
                    "token": token
                })
                print(resp.get("status"), resp.get("message", ""))

            elif cmd == "listmembers":
                if len(parts) < 2:
                    print("Usage: listMembers <group>")
                    continue
                require_token()
                resp = group_conn.call({
                    "op": "listMembers",
                    "groupName": parts[1],
                    "token": token
                })
                if resp.get("status") == "ok":
                    print("Members:", ", ".join(resp.get("members", [])))
                else:
                    print("Error:", resp.get("message"))

            elif cmd == "listfiles":
                require_token()
                resp = file_conn.call({
                    "op": "listFiles",
                    "token": token,
                    "token_signature": token_signature
                })
                if resp.get("status") == "ok":
                    print("Files:")
                    for f in resp.get("files", []):
                        print(" ", f)
                else:
                    print("Error:", resp.get("message"))

            elif cmd == "upload":
                if len(parts) < 4:
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
                    "token_signature": token_signature,
                    "groupName": group,
                    "destFile": remote,
                    "data": data_b64,
                })
                print(resp.get("status"), resp.get("message", ""))

            elif cmd == "download":
                if len(parts) < 3:
                    print("Usage: download <remote> <local>")
                    continue
                require_token()
                source = parts[1]
                local = parts[2]
                resp = file_conn.call({
                    "op": "download",
                    "token": token,
                    "token_signature": token_signature,
                    "sourceFile": source
                })
                if resp.get("status") != "ok":
                    print("Error:", resp.get("message"))
                    continue
                data_b64 = resp.get("data")
                if data_b64 is None:
                    print("No data in response")
                    continue
                with open(local, "wb") as f:
                    f.write(base64.b64decode(data_b64))
                print(f"✓ Wrote {local}")

            elif cmd == "token":
                if token is None:
                    print("No token yet (run getToken <user> <password>)")
                else:
                    print(json.dumps(token, indent=2))

            else:
                print("Unknown command:", cmd)

        except Exception as e:
            print(f"✗ Error: {e}")

    group_conn.close()
    file_conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phase 3 client (cryptographically hardened)")
    parser.add_argument("--group-host", default="localhost")
    parser.add_argument("--group-port", type=int, default=12345)
    parser.add_argument("--file-host", default="localhost")
    parser.add_argument("--file-port", type=int, default=12346)
    args = parser.parse_args()

    group_conn = ServerConnection(args.group_host, args.group_port)
    file_conn = ServerConnection(args.file_host, args.file_port)

    interactive(group_conn, file_conn)
