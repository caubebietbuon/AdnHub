"""Prepare an offline Luau tracing bundle; run only in a local pinned container.

No downloads. Default is preparation only. An offline container is NOT a proof
of perfect isolation: run inside a disposable disconnected VM for stronger containment.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parent
MAX_CAPTURE = 4 * 1024 * 1024


def literal(data: bytes) -> str:
    # Fixed-width decimal escapes cannot inject a closing quote or Lua code.
    return '"' + "".join(f"\\{byte:03d}" for byte in data) + '"'


def prepare(bundle: Path, adapter: bytes, data: bytes) -> dict:
    if len(adapter) > 65536 or len(data) > 1048576:
        raise ValueError("Adapter/data exceed limits")
    adapter.decode("utf-8")
    harness = (ROOT / "sandbox_tracer.luau").read_text(encoding="utf-8")
    entry = "local run = (function()\n" + harness + "\nend)()\nrun(" + literal(adapter) + "," + literal(data) + ")\n"
    bundle.mkdir(parents=True, exist_ok=True)
    path = bundle / "entry.luau"
    path.write_text(entry, encoding="utf-8")
    manifest = {"adapter_sha256": hashlib.sha256(adapter).hexdigest(),
                "data_sha256": hashlib.sha256(data).hexdigest(),
                "harness_sha256": hashlib.sha256(harness.encode()).hexdigest(),
                "entry_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "payload_executed": False, "status": "prepared_not_executed"}
    (bundle / "bundle-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def local_docker() -> str:
    executable = shutil.which("docker")
    if not executable:
        raise ValueError("Docker unavailable; bundle is prepared, no tracing occurred")
    explicit = os.environ.get("DOCKER_HOST", "")
    if explicit and not explicit.startswith(("unix://", "npipe://")):
        raise ValueError("Remote Docker endpoint denied")
    info = subprocess.run([executable, "context", "inspect"], check=True, capture_output=True, timeout=10)
    contexts = json.loads(info.stdout)
    endpoint = contexts[0]["Endpoints"]["docker"]["Host"]
    if not endpoint.startswith(("unix://", "npipe://")):
        raise ValueError("Docker context must use a local pipe/socket")
    return executable


def command(docker: str, image: str, bundle: Path, name: str) -> list[str]:
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise ValueError("Image must be a local immutable sha256 image ID")
    source = str(bundle.resolve())
    if "," in source:
        raise ValueError("Commas are not allowed in bundle mount paths")
    return [docker, "run", "--rm", "--pull=never", "--name", name,
            "--network=none", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true", "--memory=256m", "--memory-swap=256m",
            "--cpus=1", "--pids-limit=32", "--user=65534:65534", "--log-driver=none",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m", "--workdir", "/work",
            "--mount", f"type=bind,source={source},target=/work,readonly",
            "--entrypoint", "/usr/local/bin/luau", image, "/work/entry.luau"]


def execute(bundle: Path, image: str, output: Path, timeout: int) -> dict:
    docker = local_docker()
    args = command(docker, image, bundle, "adnhub-trace-" + uuid.uuid4().hex)
    name = args[args.index("--name") + 1]
    # inspect never pulls an image; entrypoint is supplied explicitly below.
    subprocess.run([docker, "image", "inspect", image], check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.PIPE, timeout=10)
    capture = bytearray()
    overflow = threading.Event()
    proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def read_output() -> None:
        assert proc.stdout is not None
        while True:
            chunk = proc.stdout.read(4096)
            if not chunk: break
            room = MAX_CAPTURE - len(capture)
            capture.extend(chunk[:room])
            if len(chunk) > room:
                overflow.set()
                break

    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()
    deadline = time.monotonic() + timeout
    stop = "process_exit"
    try:
        while proc.poll() is None:
            if overflow.is_set(): stop = "stdout_limit"; break
            if time.monotonic() >= deadline: stop = "wall_clock_limit"; break
            try: proc.wait(timeout=0.1)
            except subprocess.TimeoutExpired: pass
    finally:
        # Killing the Docker client alone does not guarantee container removal.
        cleanup_error = None
        try:
            subprocess.run([docker, "rm", "--force", name], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=10, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            cleanup_error = str(exc)
        finally:
            if proc.poll() is None: proc.kill()
            proc.wait(timeout=5)
            reader.join(timeout=5)
        if cleanup_error:
            raise ValueError(f"Container cleanup unconfirmed for {name}: {cleanup_error}")
    if overflow.is_set(): stop = "stdout_limit"
    if reader.is_alive(): raise ValueError("Output reader did not stop")
    output.mkdir(parents=True, exist_ok=True)
    (output / "trace.stdout.log").write_bytes(capture)
    events, non_json = [], 0
    for line in capture.splitlines():
        try:
            value = json.loads(line)
            if isinstance(value, dict) and "event" in value: events.append(value)
            else: non_json += 1
        except (ValueError, UnicodeDecodeError): non_json += 1
    (output / "trace-events.json").write_text(json.dumps(events, indent=2) + "\n", encoding="utf-8")
    snapshots = [event for event in events if event["event"] == "pre_dispatch_snapshot"]
    if snapshots:
        (output / "constant-candidate-snapshot.json").write_text(json.dumps({
            "status": "bounded_adapter_checkpoint_not_verified_complete_constants",
            "snapshots": snapshots}, indent=2) + "\n", encoding="utf-8")
    result = {"status": "isolated_process_attempted", "docker_client_exit_code": proc.returncode,
              "stop_reason": stop, "stdout_bytes": len(capture), "event_count": len(events),
              "checkpoint_snapshots": len(snapshots), "non_json_lines": non_json,
              "os_network": "container_network_none", "image_id": image,
              "warning": "Not an absolute air-gap guarantee. Checkpoint placement and adapter behavior require independent review."}
    (output / "run-result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--demo", action="store_true", help="Synthetic fixture, not recovered constants")
    cli.add_argument("--adapter", type=Path)
    cli.add_argument("--data", type=Path)
    cli.add_argument("--reviewed-adapter-sha256")
    cli.add_argument("--output", type=Path, default=Path("output/tracer"))
    cli.add_argument("--run-isolated", action="store_true")
    cli.add_argument("--image-id")
    cli.add_argument("--timeout", type=int, default=10)
    args = cli.parse_args()
    try:
        if not 1 <= args.timeout <= 30: raise ValueError("Timeout must be between 1 and 30 seconds")
        if args.demo:
            if args.adapter or args.data: raise ValueError("Demo cannot accept external adapter/data")
            adapter = (ROOT / "tracer_demo_adapter.luau").read_bytes()
            data = b"synthetic fixture, not d"
        else:
            if not args.adapter or not args.data or not args.reviewed_adapter_sha256:
                raise ValueError("Provide --demo, or a reviewed adapter/hash and data path")
            with args.adapter.open("rb") as stream: adapter = stream.read(65537)
            with args.data.open("rb") as stream: data = stream.read(1048577)
            if hashlib.sha256(adapter).hexdigest() != args.reviewed_adapter_sha256:
                raise ValueError("Reviewed adapter hash mismatch")
        if args.run_isolated and not args.image_id: raise ValueError("A local immutable --image-id is required")
        # Create a fresh bundle: no unreviewed extra files are mounted.
        run_output = args.output / ("run-" + uuid.uuid4().hex)
        bundle = run_output / "bundle"
        manifest = prepare(bundle, adapter, data)
        print("Prepared:", bundle, "adapter SHA-256:", manifest["adapter_sha256"])
        if not args.run_isolated:
            print("NOT EXECUTED. To run requires a local Luau container image and --run-isolated.")
            return 0
        result = execute(bundle, args.image_id, run_output, args.timeout)
        print(json.dumps(result, indent=2))
        return 0 if result["stop_reason"] == "process_exit" and result["docker_client_exit_code"] == 0 and result["checkpoint_snapshots"] else 1
    except (ValueError, OSError, subprocess.SubprocessError, KeyError) as exc:
        print(f"Tracer stopped: {exc}", file=sys.stderr); return 1


if __name__ == "__main__": raise SystemExit(main())
