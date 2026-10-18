"""Loads configuration, preferring the encrypted .env.enc when a MASTER_KEY is present."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from cve_pipeline.crypto_env import decrypt_to_dict

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _load_environment() -> None:
    enc_path = PROJECT_ROOT / ".env.enc"
    plain_path = PROJECT_ROOT / ".env"

    if os.environ.get("MASTER_KEY") and enc_path.exists():
        for key, value in decrypt_to_dict(enc_path).items():
            os.environ.setdefault(key, value)
    elif plain_path.exists():
        load_dotenv(plain_path)
    # else: rely on variables already exported into the environment
    # (e.g. Docker/K8s secrets, CI variables).


_load_environment()


@dataclass(frozen=True)
class Settings:
    hf_token: str
    hf_model_id: str
    nvd_api_key: str | None
    flask_secret_key: str
    msf_rpc_host: str
    msf_rpc_port: int
    msf_rpc_password: str
    msf_rpc_ssl: bool


def get_settings() -> Settings:
    """Reads whatever configuration is present; does not validate any single
    field, since which fields are required depends on what the caller does
    (the LLM pipeline needs HF_TOKEN, the live EternalBlue runner needs the
    MSF_RPC_* settings, the live vsftpd runner needs neither).
    """
    return Settings(
        hf_token=os.environ.get("HF_TOKEN", ""),
        hf_model_id=os.environ.get("HF_MODEL_ID", "Qwen/Qwen2.5-Coder-32B-Instruct"),
        nvd_api_key=os.environ.get("NVD_API_KEY") or None,
        flask_secret_key=os.environ.get("FLASK_SECRET_KEY", "dev-secret"),
        msf_rpc_host=os.environ.get("MSF_RPC_HOST", "127.0.0.1"),
        msf_rpc_port=int(os.environ.get("MSF_RPC_PORT", "55553")),
        msf_rpc_password=os.environ.get("MSF_RPC_PASSWORD", ""),
        msf_rpc_ssl=os.environ.get("MSF_RPC_SSL", "true").lower() != "false",
    )
