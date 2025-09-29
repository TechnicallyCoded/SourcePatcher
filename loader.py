#!/usr/bin/env python3
# secure_run_remote_ed25519_hash.py
#
# Commands:
#   remote <url> [args...]              # verify + run from URL, pass args to target
#   download <url> [args...]            # alias of remote
#   run <py_file> [args...]             # verify + run local file, pass args
#   verify <py_file>                    # verify only
#   sign <py_file> <ed25519_priv_pem>   # rewrite header with fresh HASH+SIGNATURE
#   exec [args...]                      # like default remote DEFAULT_URL, pass args
# Default (no args): remote DEFAULT_URL (no args passed)
#
# Requires: cryptography  (python3 -m pip install cryptography)

import base64
import hashlib
import sys
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
    Ed25519PrivateKey,
)
from cryptography.exceptions import InvalidSignature

# Trusted Ed25519 public key (PEM)
PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA6o1rbi7P0JXgiJwk71bVR4tddPmsPhqwBtdYrEWwc2Q=
-----END PUBLIC KEY-----
"""

DEFAULT_URL = "https://raw.githubusercontent.com/TechnicallyCoded/SourcePatcher/refs/heads/main/source_patcher.py"


# -------- helpers --------

def _require_comment(line: str) -> str:
    if not line.startswith("#"):
        raise ValueError("header contains non-comment line")
    return line[1:].strip()

def _load_pubkey() -> Ed25519PublicKey:
    pub = serialization.load_pem_public_key(PUBLIC_KEY_PEM)
    if not isinstance(pub, Ed25519PublicKey):
        raise ValueError("PUBLIC_KEY_PEM is not Ed25519")
    return pub

def _fetch_bytes(url: str) -> bytes:
    with urllib.request.urlopen(url) as r:
        return r.read()

def _parse_and_verify(payload: bytes, verbose: bool = False) -> bytes:
    text = payload.decode("utf-8", errors="strict")
    lines = text.splitlines()
    i = 0
    if not lines:
        raise ValueError("empty file")

    if _require_comment(lines[i]) != "HEADER":
        raise ValueError("missing '# HEADER'")
    i += 1

    while i < len(lines):
        tok = _require_comment(lines[i])
        if tok == "HASH":
            break
        i += 1
    if i >= len(lines):
        raise ValueError("missing '# HASH'")
    i += 1

    if i >= len(lines):
        raise ValueError("missing hash value")
    hash_hex = _require_comment(lines[i]).lower()
    if len(hash_hex) != 128 or any(c not in "0123456789abcdef" for c in hash_hex):
        raise ValueError("invalid sha512 hex")
    i += 1

    if i >= len(lines) or _require_comment(lines[i]) != "SIGNATURE":
        raise ValueError("missing '# SIGNATURE'")
    i += 1

    if i >= len(lines):
        raise ValueError("missing signature value")
    sig_b64 = _require_comment(lines[i])
    i += 1

    if i >= len(lines) or _require_comment(lines[i]) != "END":
        raise ValueError("missing '# END'")
    i += 1

    if i >= len(lines) or _require_comment(lines[i]) != "---":
        raise ValueError("missing '# ---'")
    i += 1

    header_text = "\n".join(lines[:i]) + "\n"
    body = payload[len(header_text.encode("utf-8")):]

    actual_hash = hashlib.sha512(body).hexdigest()
    if actual_hash != hash_hex:
        raise ValueError("hash mismatch")

    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except Exception as e:
        raise ValueError(f"invalid base64 signature: {e}") from e
    if len(sig) != 64:
        raise ValueError("invalid Ed25519 signature length")

    pub = _load_pubkey()
    try:
        pub.verify(sig, bytes.fromhex(actual_hash))
    except InvalidSignature:
        raise ValueError("signature verification failed")

    if verbose:
        print("Verification successful.")
        print(f"SHA-512: {actual_hash}")
    return body

def _exec_verified(body: bytes, src_label: str, argv_for_target: list[str]):
    # Replace sys.argv for the duration of the target execution
    old_argv = sys.argv
    try:
        sys.argv = argv_for_target
        ns = {"__name__": "__main__", "__file__": src_label}
        exec(compile(body.decode("utf-8"), src_label, "exec"), ns)
    finally:
        sys.argv = old_argv


# -------- modes --------

def cmd_remote(url: str, target_args: list[str]):
    payload = _fetch_bytes(url)
    body = _parse_and_verify(payload)
    _exec_verified(body, url, [url] + target_args)

def cmd_run_local(py_path: Path, target_args: list[str]):
    payload = py_path.read_bytes()
    body = _parse_and_verify(payload)
    _exec_verified(body, str(py_path), [str(py_path)] + target_args)

def cmd_verify_local(py_path: Path):
    payload = py_path.read_bytes()
    _parse_and_verify(payload, verbose=True)

def cmd_sign_in_place(py_path: Path, privkey_path: Path):
    data = py_path.read_bytes()
    text = data.decode("utf-8", errors="strict")
    lines = text.splitlines()

    # find '# ---' to locate body start; body is everything after it
    for idx, line in enumerate(lines):
        if line.strip() == "# ---":
            body = "\n".join(lines[idx + 1 :]).encode("utf-8")
            break
    else:
        raise SystemExit("file missing '# ---' line")

    body_hash_hex = hashlib.sha512(body).hexdigest()

    with privkey_path.open("rb") as f:
        sk = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(sk, Ed25519PrivateKey):
        raise SystemExit("provided key is not Ed25519")

    sig = sk.sign(bytes.fromhex(body_hash_hex))
    sig_b64 = base64.b64encode(sig).decode()

    header_lines = [
        "# HEADER",
        "# HASH",
        f"# {body_hash_hex}",
        "# SIGNATURE",
        f"# {sig_b64}",
        "# END",
        "# ---",
    ]
    new_content = ("\n".join(header_lines) + "\n").encode("utf-8") + body
    tmp = py_path.with_suffix(py_path.suffix + ".tmp")
    tmp.write_bytes(new_content)
    tmp.replace(py_path)


# -------- CLI --------

def _usage():
    print(
        "usage:\n"
        "  script.py                          # remote DEFAULT_URL (no args)\n"
        "  script.py exec [args...]           # remote DEFAULT_URL, pass args to target\n"
        "  script.py remote <url> [args...]   # verify + run from URL, pass args\n"
        "  script.py download <url> [args...] # alias of remote\n"
        "  script.py run <py_file> [args...]  # verify + run local file, pass args\n"
        "  script.py verify <py_file>         # verify local file only\n"
        "  script.py sign <py> <ed25519_priv_pem>\n",
        file=sys.stderr,
    )

def main():
    if len(sys.argv) == 1:
        # default: remote DEFAULT_URL with no args to target
        cmd_remote(DEFAULT_URL, [])
        return

    cmd = sys.argv[1]

    if cmd == "exec":
        # exec [args...] -> remote DEFAULT_URL, pass args to target
        target_args = sys.argv[2:]
        cmd_remote(DEFAULT_URL, target_args)

    elif cmd in ("remote", "download"):
        if len(sys.argv) < 3:
            _usage(); sys.exit(2)
        url = sys.argv[2]
        target_args = sys.argv[3:]
        cmd_remote(url, target_args)

    elif cmd == "run":
        if len(sys.argv) < 3:
            _usage(); sys.exit(2)
        path = Path(sys.argv[2])
        target_args = sys.argv[3:]
        cmd_run_local(path, target_args)

    elif cmd == "verify":
        if len(sys.argv) != 3:
            _usage(); sys.exit(2)
        cmd_verify_local(Path(sys.argv[2]))

    elif cmd == "sign":
        if len(sys.argv) != 4:
            _usage(); sys.exit(2)
        cmd_sign_in_place(Path(sys.argv[2]), Path(sys.argv[3]))

    else:
        _usage(); sys.exit(2)

if __name__ == "__main__":
    main()
