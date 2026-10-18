"""Encrypt/decrypt the project's .env file with a Fernet master key.

The master key itself is never committed: export it as the MASTER_KEY
environment variable (locally, in CI, or as a Docker/K8s secret). Only the
resulting .env.enc ciphertext is checked into git.

Usage:
    uv run python -m cve_pipeline.crypto_env gen-key
    uv run python -m cve_pipeline.crypto_env encrypt .env .env.enc
    uv run python -m cve_pipeline.crypto_env decrypt .env.enc
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


def generate_key() -> str:
    return Fernet.generate_key().decode()


def _get_master_key() -> bytes:
    key = os.environ.get("MASTER_KEY")
    if not key:
        raise SystemExit(
            "MASTER_KEY environment variable is not set. "
            "Run 'gen-key' once and export the result as MASTER_KEY."
        )
    return key.encode()


def encrypt_file(plaintext_path: Path, ciphertext_path: Path) -> None:
    fernet = Fernet(_get_master_key())
    data = plaintext_path.read_bytes()
    ciphertext_path.write_bytes(fernet.encrypt(data))


def decrypt_file(ciphertext_path: Path) -> str:
    fernet = Fernet(_get_master_key())
    try:
        return fernet.decrypt(ciphertext_path.read_bytes()).decode()
    except InvalidToken as exc:
        raise SystemExit("Decryption failed: wrong MASTER_KEY or corrupted .env.enc") from exc


def decrypt_to_dict(ciphertext_path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in decrypt_file(ciphertext_path).splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


def main() -> None:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        raise SystemExit(1)

    command, *rest = args
    if command == "gen-key":
        print(generate_key())
    elif command == "encrypt":
        src, dst = (rest + [".env", ".env.enc"])[:2]
        encrypt_file(Path(src), Path(dst))
        print(f"Encrypted {src} -> {dst}")
    elif command == "decrypt":
        src = rest[0] if rest else ".env.enc"
        print(decrypt_file(Path(src)))
    else:
        print(__doc__)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
