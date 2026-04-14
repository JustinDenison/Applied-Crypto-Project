#!/usr/bin/env python3
"""Phase 3 Group Server - Cryptographically Hardened (TCP + JSON + AES-256-GCM)

Security features:
- T1: Password-based authentication (PBKDF2-SHA256)
- T2: Ed25519 token signing
- T3: AES-256-GCM message encryption
- T4: Nonce/timestamp replay protection
- T5: ECDHE (X25519) for forward secrecy
- T6: Session keys ephemeral (per-connection)
"""

import json
import os
import socket
import threading
import time
import secrets
import hashlib
import hmac
from typing import Dict, Any, Optional, Tuple
from base64 import b64encode, b64decode

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


STATE_FILE = "groupserver_state.json"

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 12345

NONCE_CACHE_TTL = 3600
TIMESTAMP_TOLERANCE = 60


def hash_password(password: str) -> str:
    """Hash password using PBKDF2-SHA256"""
    iterations = 100000
    salt = secrets.token_bytes(16)
    hash_obj = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)
    return f"$pbkdf2$v=1$iterations={iterations}$salt={salt.hex()}$hash={hash_obj.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored hash"""
    try:
        parts = stored_hash.split("$")
        # Expected format: $pbkdf2$v=1$iterations=100000$salt=<hex>$hash=<hex>
        if len(parts) < 6 or parts[1] != "pbkdf2":
            return False
        iterations = int(parts[3].split("=")[1])
        salt = bytes.fromhex(parts[4].split("=")[1])
        stored_hash_hex = parts[5].split("=")[1]
        computed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)
        return hmac.compare_digest(computed.hex(), stored_hash_hex)
    except Exception:
        return False


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
    try:
        plaintext = cipher.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")
    return json.loads(plaintext.decode("utf-8"))


def establish_session_key(client_public_b64: str) -> Tuple[str, bytes]:
    """ECDHE: Perform key exchange and return (server_public, session_key)"""
    client_public_bytes = b64decode(client_public_b64)
    client_public = x25519.X25519PublicKey.from_public_bytes(client_public_bytes)
    
    server_private = x25519.X25519PrivateKey.generate()
    server_public = server_private.public_key()
    shared_secret = server_private.exchange(client_public)
    
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=b"session_key")
    session_key = hkdf.derive(shared_secret)
    
    server_public_b64 = b64encode(
        server_public.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    ).decode("utf-8")
    
    return server_public_b64, session_key


def sign_token(token_dict: Dict[str, Any], private_key: ed25519.Ed25519PrivateKey) -> str:
    """Sign token with Ed25519"""
    message = json.dumps(token_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = private_key.sign(message)
    return b64encode(signature).decode("utf-8")


def validate_nonce_timestamp(request: Dict[str, Any], nonce_cache: Dict[str, list], session_id: str) -> Tuple[bool, str]:
    """Validate nonce freshness and timestamp"""
    nonce = request.get("nonce")
    timestamp = request.get("timestamp")
    
    if not nonce or not timestamp:
        return False, "Missing nonce or timestamp"
    
    current_time = time.time()
    if abs(current_time - timestamp) > TIMESTAMP_TOLERANCE:
        return False, f"Timestamp out of tolerance: {abs(current_time - timestamp):.1f}s"
    
    if session_id not in nonce_cache:
        nonce_cache[session_id] = []
    
    if nonce in nonce_cache[session_id]:
        return False, "Nonce replay detected"
    
    nonce_cache[session_id].append(nonce)
    return True, ""


def send_encrypted_json(conn: socket.socket, obj: Dict[str, Any], session_key: bytes) -> None:
    """Send encrypted JSON"""
    encrypted_b64 = encrypt_message(obj, session_key)
    wrapper = {"encrypted": encrypted_b64}
    data = json.dumps(wrapper, separators=(",", ":")) + "\n"
    conn.sendall(data.encode("utf-8"))


def recv_encrypted_json(conn: socket.socket, session_key: bytes) -> Optional[Dict[str, Any]]:
    """Receive encrypted JSON"""
    line = b""
    while not line.endswith(b"\n"):
        chunk = conn.recv(4096)
        if not chunk:
            return None
        line += chunk
    try:
        wrapper = json.loads(line.decode("utf-8").strip())
        encrypted_b64 = wrapper.get("encrypted")
        if not encrypted_b64:
            return None
        return decrypt_message(encrypted_b64, session_key)
    except Exception:
        return None


def send_json_unencrypted(conn: socket.socket, obj: Dict[str, Any]) -> None:
    """Send unencrypted JSON (only for ECDHE handshake)"""
    data = json.dumps(obj, separators=(",", ":")) + "\n"
    conn.sendall(data.encode("utf-8"))


def recv_json_unencrypted(conn: socket.socket) -> Optional[Dict[str, Any]]:
    """Receive unencrypted JSON (only for ECDHE handshake)"""
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


def load_state() -> Dict[str, Any]:
    state = None
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            state = json.load(f)

    if state is None:
        admin_pwd_hash = hash_password("admin123")
        return {
            "users": ["admin"],
            "user_passwords": {"admin": admin_pwd_hash},
            "groups": {"ADMIN": {"owner": "admin", "members": ["admin"]}},
            "server_signing_key_private": None,
            "nonce_cache": {},
        }

    mutated = False
    if "users" not in state:
        state["users"] = ["admin"]
        mutated = True
    if "user_passwords" not in state:
        state["user_passwords"] = {}
        mutated = True
    if "groups" not in state:
        state["groups"] = {"ADMIN": {"owner": "admin", "members": ["admin"]}}
        mutated = True
    if "server_signing_key_private" not in state:
        state["server_signing_key_private"] = None
        mutated = True
    if "nonce_cache" not in state:
        state["nonce_cache"] = {}
        mutated = True

    if "admin" in state["users"] and "admin" not in state["user_passwords"]:
        state["user_passwords"]["admin"] = hash_password("admin123")
        mutated = True
    for user in state["users"]:
        if user not in state["user_passwords"]:
            state["user_passwords"][user] = hash_password("changeme")
            mutated = True

    if mutated:
        save_state(state)

    return state


def save_state(state: Dict[str, Any]) -> None:
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def make_token(user: str, state: Dict[str, Any]) -> Dict[str, Any]:
    user_groups = [g for g, info in state["groups"].items() if user in info["members"]]
    return {
        "userName": user,
        "groups": sorted(user_groups),
        "exp": int(time.time()) + 3600
    }


def load_or_create_signing_key(state: Dict[str, Any]) -> ed25519.Ed25519PrivateKey:
    """Load or create server's Ed25519 signing key"""
    if state.get("server_signing_key_private"):
        private_bytes = b64decode(state["server_signing_key_private"])
        return ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
    
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    state["server_signing_key_private"] = b64encode(private_bytes).decode("utf-8")
    save_state(state)
    print("[GroupServer] Generated new Ed25519 signing key")
    return private_key


def handle_client(conn: socket.socket, addr, state: Dict[str, Any], private_key: ed25519.Ed25519PrivateKey, lock: threading.Lock) -> None:
    session_id = f"{addr[0]}:{addr[1]}_{time.time()}"
    session_key = None
    
    try:
        # ECDHE handshake
        client_pub_msg = recv_json_unencrypted(conn)
        if not client_pub_msg or "client_ephemeral_public" not in client_pub_msg:
            send_json_unencrypted(conn, {"status": "error", "message": "Expected ephemeral public key"})
            return
        
        server_public_b64, session_key = establish_session_key(client_pub_msg["client_ephemeral_public"])
        
        nonce = b64encode(secrets.token_bytes(16)).decode()
        send_json_unencrypted(conn, {
            "status": "ok",
            "server_ephemeral_public": server_public_b64,
            "nonce": nonce
        })
        
        print(f"[GroupServer] {addr} connected, session established")
        
        # Encrypted request loop
        while True:
            encrypted_req = recv_encrypted_json(conn, session_key)
            if encrypted_req is None:
                break
            
            op = encrypted_req.get("op")
            if not op:
                send_encrypted_json(conn, {"status": "error", "message": "Missing op"}, session_key)
                continue
            
            # Validate nonce/timestamp
            is_valid, error_msg = validate_nonce_timestamp(encrypted_req, state["nonce_cache"], session_id)
            if not is_valid:
                send_encrypted_json(conn, {"status": "error", "message": error_msg}, session_key)
                continue
            
            if op == "getToken":
                user = encrypted_req.get("userName")
                password = encrypted_req.get("password")
                
                if not user or not password:
                    send_encrypted_json(conn, {"status": "error", "message": "Missing userName or password"}, session_key)
                    continue
                
                with lock:
                    user_hash = state.get("user_passwords", {}).get(user)
                if not user_hash or not verify_password(password, user_hash):
                    send_encrypted_json(conn, {"status": "error", "message": "Authentication failed"}, session_key)
                    continue
                
                with lock:
                    if user not in state["users"]:
                        state["users"].append(user)
                        state["user_passwords"][user] = hash_password(password)
                        save_state(state)
                    token = make_token(user, state)
                
                token_signature = sign_token(token, private_key)
                send_encrypted_json(conn, {
                    "status": "ok",
                    "token": token,
                    "token_signature": token_signature,
                    "nonce": encrypted_req["nonce"]
                }, session_key)
            
            elif op == "createUser":
                token = encrypted_req.get("token")
                new_user = encrypted_req.get("userName")
                password = encrypted_req.get("password", "changeme")
                
                if not token or not new_user:
                    send_encrypted_json(conn, {"status": "error", "message": "Missing token or userName"}, session_key)
                    continue
                
                caller = token.get("userName")
                caller_groups = token.get("groups", [])
                if "ADMIN" not in caller_groups:
                    send_encrypted_json(conn, {"status": "error", "message": "Must be ADMIN to create user"}, session_key)
                    continue
                
                with lock:
                    if new_user in state["users"]:
                        send_encrypted_json(conn, {"status": "error", "message": "User already exists"}, session_key)
                        continue
                    state["users"].append(new_user)
                    state["user_passwords"][new_user] = hash_password(password)
                    save_state(state)
                
                send_encrypted_json(conn, {"status": "ok", "nonce": encrypted_req["nonce"]}, session_key)
            
            elif op == "createGroup":
                token = encrypted_req.get("token")
                group = encrypted_req.get("groupName")
                
                if not token or not group:
                    send_encrypted_json(conn, {"status": "error", "message": "Missing token or groupName"}, session_key)
                    continue
                
                caller = token.get("userName")
                if group in state["groups"]:
                    send_encrypted_json(conn, {"status": "error", "message": "Group already exists"}, session_key)
                    continue
                
                with lock:
                    state["groups"][group] = {"owner": caller, "members": [caller]}
                    save_state(state)
                
                send_encrypted_json(conn, {"status": "ok", "nonce": encrypted_req["nonce"]}, session_key)
            
            elif op == "addUserToGroup":
                token = encrypted_req.get("token")
                group = encrypted_req.get("groupName")
                user = encrypted_req.get("userName")
                
                if not token or not group or not user:
                    send_encrypted_json(conn, {"status": "error", "message": "Missing token, groupName, or userName"}, session_key)
                    continue
                
                caller = token.get("userName")
                group_info = state["groups"].get(group)
                if not group_info:
                    send_encrypted_json(conn, {"status": "error", "message": "Unknown group"}, session_key)
                    continue
                
                if group_info["owner"] != caller:
                    send_encrypted_json(conn, {"status": "error", "message": "Only the group owner can add users"}, session_key)
                    continue
                
                with lock:
                    if user not in state["users"]:
                        state["users"].append(user)
                        state["user_passwords"][user] = hash_password("changeme")
                    if user not in group_info["members"]:
                        group_info["members"].append(user)
                    save_state(state)
                
                send_encrypted_json(conn, {"status": "ok", "nonce": encrypted_req["nonce"]}, session_key)
            
            elif op == "listMembers":
                token = encrypted_req.get("token")
                group = encrypted_req.get("groupName")
                
                if not token or not group:
                    send_encrypted_json(conn, {"status": "error", "message": "Missing token or groupName"}, session_key)
                    continue
                
                caller = token.get("userName")
                group_info = state["groups"].get(group)
                if not group_info:
                    send_encrypted_json(conn, {"status": "error", "message": "Unknown group"}, session_key)
                    continue
                
                if group_info["owner"] != caller:
                    send_encrypted_json(conn, {"status": "error", "message": "Only the group owner can list members"}, session_key)
                    continue
                
                send_encrypted_json(conn, {
                    "status": "ok",
                    "members": sorted(group_info["members"]),
                    "nonce": encrypted_req["nonce"]
                }, session_key)
            
            elif op == "disconnect":
                send_encrypted_json(conn, {"status": "ok"}, session_key)
                break
            
            else:
                send_encrypted_json(conn, {"status": "error", "message": f"Unknown op: {op}"}, session_key)
    
    except Exception as e:
        print(f"[GroupServer] Error {addr}: {e}")
    finally:
        conn.close()


def serve(host: str, port: int) -> None:
    state = load_state()
    private_key = load_or_create_signing_key(state)
    lock = threading.Lock()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)
    print(f"[GroupServer] Listening on {host}:{port}")
    
    try:
        while True:
            conn, addr = sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr, state, private_key, lock), daemon=True)
            t.start()
    finally:
        sock.close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Phase 3 Group Server (Cryptographically Hardened)")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Host to bind")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to bind")
    args = parser.parse_args()
    serve(args.host, args.port)
