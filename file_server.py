#!/usr/bin/env python3
"""Phase 3 File Server - Cryptographically Hardened (TCP + JSON + AES-256-GCM)

Security features:
- T2: Ed25519 token signature verification
- T3: AES-256-GCM message encryption
- T4: Nonce/timestamp replay protection
- T5: ECDHE (X25519) for forward secrecy
"""

import base64
import json
import os
import socket
import threading
import time
import secrets
from typing import Dict, Any, Optional, Tuple
from base64 import b64encode, b64decode

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

METADATA_FILE = "fileserver_metadata.json"
STORAGE_DIR = "storage"

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 12346

NONCE_CACHE_TTL = 3600
TIMESTAMP_TOLERANCE = 60


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


def verify_token_signature(token_dict: Dict[str, Any], signature_b64: str, public_key: ed25519.Ed25519PublicKey) -> bool:
    """Verify Ed25519 token signature"""
    message = json.dumps(token_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = b64decode(signature_b64)
    try:
        public_key.verify(signature, message)
        return True
    except Exception:
        return False


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


def load_metadata() -> Dict[str, Any]:
    metadata = {}
    if os.path.exists(METADATA_FILE):
        with open(METADATA_FILE, "r", encoding="utf-8") as f:
            loaded = json.load(f)
            metadata.update(loaded)
    
    # Ensure required keys exist
    if "files" not in metadata:
        metadata["files"] = {}
    if "nonce_cache" not in metadata:
        metadata["nonce_cache"] = {}
    
    return metadata


def save_metadata(md: Dict[str, Any]) -> None:
    with open(METADATA_FILE, "w", encoding="utf-8") as f:
        json.dump(md, f, indent=2)


def ensure_storage_dir() -> None:
    os.makedirs(STORAGE_DIR, exist_ok=True)


def load_group_server_public_key() -> ed25519.Ed25519PublicKey:
    """Load group server's public key from state file"""
    try:
        with open("groupserver_state.json", "r", encoding="utf-8") as f:
            gs_state = json.load(f)
        
        if gs_state.get("server_signing_key_private"):
            private_bytes = b64decode(gs_state["server_signing_key_private"])
            priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
            return priv_key.public_key()
    except Exception as e:
        print(f"[FileServer] Warning: Could not load group server public key: {e}")
    
    raise RuntimeError("Cannot verify tokens without group server public key")


def handle_client(conn: socket.socket, addr, metadata: Dict[str, Any], public_key: ed25519.Ed25519PublicKey, lock: threading.Lock) -> None:
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
        
        print(f"[FileServer] {addr} connected, session established")
        
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
            is_valid, error_msg = validate_nonce_timestamp(encrypted_req, metadata["nonce_cache"], session_id)
            if not is_valid:
                send_encrypted_json(conn, {"status": "error", "message": error_msg}, session_key)
                continue
            
            # Extract token and signature
            token = encrypted_req.get("token")
            token_signature = encrypted_req.get("token_signature")
            
            if op == "listFiles":
                if not token or not token_signature:
                    send_encrypted_json(conn, {"status": "error", "message": "Missing token or signature"}, session_key)
                    continue
                
                if not verify_token_signature(token, token_signature, public_key):
                    send_encrypted_json(conn, {"status": "error", "message": "Invalid token signature"}, session_key)
                    continue
                
                user = token.get("userName")
                groups = set(token.get("groups", []))
                files = []
                for name, info in metadata.get("files", {}).items():
                    if info.get("group") in groups:
                        files.append(name)
                
                send_encrypted_json(conn, {
                    "status": "ok",
                    "files": sorted(files),
                    "nonce": encrypted_req["nonce"]
                }, session_key)
            
            elif op == "upload":
                if not token or not token_signature:
                    send_encrypted_json(conn, {"status": "error", "message": "Missing token or signature"}, session_key)
                    continue
                
                if not verify_token_signature(token, token_signature, public_key):
                    send_encrypted_json(conn, {"status": "error", "message": "Invalid token signature"}, session_key)
                    continue
                
                group = encrypted_req.get("groupName")
                dest = encrypted_req.get("destFile")
                data_b64 = encrypted_req.get("data")
                user = token.get("userName")
                groups = set(token.get("groups", []))
                
                if not (group and dest and data_b64):
                    send_encrypted_json(conn, {"status": "error", "message": "Missing groupName, destFile, or data"}, session_key)
                    continue
                
                if group not in groups:
                    send_encrypted_json(conn, {"status": "error", "message": "Token not in group"}, session_key)
                    continue
                
                try:
                    file_bytes = base64.b64decode(data_b64)
                except Exception:
                    send_encrypted_json(conn, {"status": "error", "message": "Invalid base64 data"}, session_key)
                    continue
                
                ensure_storage_dir()
                dest_path = os.path.join(STORAGE_DIR, dest)
                with open(dest_path, "wb") as f:
                    f.write(file_bytes)
                
                with lock:
                    metadata.setdefault("files", {})[dest] = {"group": group, "uploadedBy": user}
                    save_metadata(metadata)
                
                send_encrypted_json(conn, {"status": "ok", "nonce": encrypted_req["nonce"]}, session_key)
            
            elif op == "download":
                if not token or not token_signature:
                    send_encrypted_json(conn, {"status": "error", "message": "Missing token or signature"}, session_key)
                    continue
                
                if not verify_token_signature(token, token_signature, public_key):
                    send_encrypted_json(conn, {"status": "error", "message": "Invalid token signature"}, session_key)
                    continue
                
                source = encrypted_req.get("sourceFile")
                groups = set(token.get("groups", []))
                
                if not source:
                    send_encrypted_json(conn, {"status": "error", "message": "Missing sourceFile"}, session_key)
                    continue
                
                file_info = metadata.get("files", {}).get(source)
                if not file_info:
                    send_encrypted_json(conn, {"status": "error", "message": "File not found"}, session_key)
                    continue
                
                if file_info.get("group") not in groups:
                    send_encrypted_json(conn, {"status": "error", "message": "Token not in file group"}, session_key)
                    continue
                
                path = os.path.join(STORAGE_DIR, source)
                if not os.path.exists(path):
                    send_encrypted_json(conn, {"status": "error", "message": "Stored file missing"}, session_key)
                    continue
                
                with open(path, "rb") as f:
                    data_b64 = base64.b64encode(f.read()).decode("utf-8")
                
                send_encrypted_json(conn, {
                    "status": "ok",
                    "data": data_b64,
                    "nonce": encrypted_req["nonce"]
                }, session_key)
            
            elif op == "disconnect":
                send_encrypted_json(conn, {"status": "ok"}, session_key)
                break
            
            else:
                send_encrypted_json(conn, {"status": "error", "message": f"Unknown op: {op}"}, session_key)
    
    except Exception as e:
        print(f"[FileServer] Error {addr}: {e}")
    finally:
        conn.close()


def serve(host: str, port: int) -> None:
    metadata = load_metadata()
    public_key = load_group_server_public_key()
    lock = threading.Lock()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)
    print(f"[FileServer] Listening on {host}:{port}")
    
    try:
        while True:
            conn, addr = sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr, metadata, public_key, lock), daemon=True)
            t.start()
    finally:
        sock.close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Phase 3 File Server (Cryptographically Hardened)")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Host to bind")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to bind")
    args = parser.parse_args()
    serve(args.host, args.port)
