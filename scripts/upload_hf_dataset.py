#!/usr/bin/env python3
import argparse
import os
import time
from pathlib import Path

from huggingface_hub import HfApi


def log(message: str) -> None:
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{stamp}] {message}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Upload prepared dataset artifacts to Hugging Face.")
    parser.add_argument("--repo-id", default="HeasoNnn/TrafficDataset")
    parser.add_argument("--folder", default="/home/hs/workspace/Glance_PT/datasets")
    parser.add_argument("--allow", action="append")
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()

    folder = Path(args.folder)
    if not folder.exists():
        raise SystemExit(f"folder not found: {folder}")

    log(f"repo_id={args.repo_id}")
    log(f"folder={folder}")
    allow_patterns = args.allow or ["pretrain_family/**"]
    log(f"allow_patterns={allow_patterns}")
    log(f"https_proxy={os.environ.get('HTTPS_PROXY', '')}")

    api = HfApi()
    api.create_repo(repo_id=args.repo_id, repo_type="dataset", private=True, exist_ok=True)
    api.upload_large_folder(
        repo_id=args.repo_id,
        repo_type="dataset",
        folder_path=folder,
        allow_patterns=allow_patterns,
        ignore_patterns=["**/.DS_Store", "**/__pycache__/**", "**/*.tmp"],
        num_workers=args.workers,
        print_report=True,
        print_report_every=30,
    )
    log("upload completed")


if __name__ == "__main__":
    main()
