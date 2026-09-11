"""Measure complete Liberty Happ profiles through Xray for speed ordering."""

import argparse
import concurrent.futures
import copy
import datetime
import json
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import build_happ_liberty as liberty


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "happ_liberty_measurements.json"
DOWNLOAD_BYTES = 262144


def available_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def curl(port, url, limit):
    result = subprocess.run(
        [
            "curl", "--silent", "--show-error", "--proxy", f"socks5h://127.0.0.1:{port}",
            "--noproxy", "", "--connect-timeout", "4", "--max-time", "10",
            "--max-filesize", str(limit), "--output", os.devnull, "--write-out", "%{json}", url,
        ],
        capture_output=True,
        text=True,
        timeout=13,
    )
    try:
        data = json.loads(result.stdout)
    except ValueError:
        data = {}
    data["exit"] = result.returncode
    return data


def measure(entry, binary):
    source_index, source = entry
    name = source.get("remarks", f"profile {source_index}")
    result = {"name": name, "source_index": source_index, "status": "unavailable"}
    config = copy.deepcopy(source)
    port = available_port()
    config["inbounds"] = [{
        "listen": "127.0.0.1", "port": port, "protocol": "socks",
        "settings": {"auth": "noauth", "udp": True},
    }]
    target = liberty.proxy_target(config)
    config.setdefault("routing", {})["rules"] = [{"type": "field", "network": "tcp,udp", **target}]
    with tempfile.TemporaryDirectory(prefix="happ-liberty-") as directory:
        path = Path(directory) / "config.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        process = subprocess.Popen(
            [binary, "run", "-format", "json", "-c", str(path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                result["reason"] = "xray_not_ready"
                return result
            latency = curl(port, "https://www.gstatic.com/generate_204", 4096)
            if latency.get("exit") or latency.get("http_code") != 204:
                result["reason"] = "latency_failed"
                return result
            speed = curl(port, f"https://speed.cloudflare.com/__down?bytes={DOWNLOAD_BYTES}", DOWNLOAD_BYTES)
            if speed.get("exit") or speed.get("http_code") != 200 or speed.get("size_download") != DOWNLOAD_BYTES:
                result["reason"] = "speed_failed"
                return result
            result.update(
                status="ok",
                latency_ms=round(latency["time_starttransfer"] * 1000),
                speed_mbps=round(speed["speed_download"] * 8 / 1_000_000, 2),
            )
            return result
        except (OSError, subprocess.TimeoutExpired, KeyError) as exc:
            result["reason"] = type(exc).__name__
            return result
        finally:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--xray", required=True)
    parser.add_argument("--workers", type=int, default=4, choices=range(1, 7))
    args = parser.parse_args()
    catalog = json.loads(liberty.CATALOG.read_text(encoding="utf-8"))
    entries = [
        (index, item)
        for index, item in enumerate(catalog)
        if not item.get("remarks", "").startswith("🇪🇺 🚀Авто")
    ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(lambda entry: measure(entry, args.xray), entries))
    OUTPUT.write_text(
        json.dumps(
            {
                "measured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "vantage": "GitHub Actions" if os.environ.get("GITHUB_ACTIONS") else "local machine",
                "sample_bytes": DOWNLOAD_BYTES,
                "results": results,
            },
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    for item in results:
        print(item["name"], item["status"], item.get("speed_mbps", "-"), flush=True)


if __name__ == "__main__":
    main()
