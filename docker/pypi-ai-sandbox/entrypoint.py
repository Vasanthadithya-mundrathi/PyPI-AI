from __future__ import annotations

import json
import os
import runpy
import subprocess
import sys
import zipfile
from pathlib import Path

telemetry = {
    "status": "complete",
    "process_events": [],
    "file_events": [],
    "network_events": [],
    "import_events": [],
}


def audit_hook(event: str, args: tuple[object, ...]) -> None:
    if event == "subprocess.Popen":
        telemetry["process_events"].append({"event": event, "args": [str(item) for item in args]})
    elif event in {"open", "os.remove", "os.rename", "os.mkdir"}:
        telemetry["file_events"].append({"event": event, "args": [str(item) for item in args]})
    elif event in {"socket.connect", "socket.getaddrinfo"}:
        telemetry["network_events"].append({"event": event, "args": [str(item) for item in args]})
    elif event == "import":
        telemetry["import_events"].append({"event": event, "module": str(args[0]) if args else ""})


def top_level_modules(wheel_path: Path) -> list[str]:
    modules: list[str] = []
    with zipfile.ZipFile(wheel_path) as archive:
        for name in archive.namelist():
            if name.endswith("top_level.txt"):
                modules.extend(
                    item.strip()
                    for item in archive.read(name).decode("utf-8", "ignore").splitlines()
                    if item.strip()
                )
        if not modules:
            for name in archive.namelist():
                if name.endswith(".py") and "/" in name:
                    candidate = name.split("/", 1)[0]
                    if candidate and candidate.endswith(".dist-info") is False:
                        modules.append(candidate)
    return sorted(set(modules))[:5]


def main() -> int:
    if len(sys.argv) != 2:
        telemetry["status"] = "failed"
        print(json.dumps({**telemetry, "reason": "expected one wheel path"}))
        return 2
    wheel_path = Path(sys.argv[1])
    if not wheel_path.exists() or wheel_path.suffix != ".whl":
        telemetry["status"] = "failed"
        print(json.dumps({**telemetry, "reason": "artifact is not a wheel"}))
        return 2

    sys.addaudithook(audit_hook)
    env = {key: value for key, value in os.environ.items() if key.startswith("PYTHON")}
    install_dir = Path("/tmp/pypi-ai-target")
    command = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--no-index",
        "--no-deps",
        "--target",
        str(install_dir),
        str(wheel_path),
    ]
    completed = subprocess.run(command, check=False, capture_output=True, text=True, env=env)
    telemetry["process_events"].append({"event": "pip-install", "returncode": completed.returncode})
    if completed.returncode != 0:
        telemetry["status"] = "failed"
        print(json.dumps({**telemetry, "reason": completed.stderr[-500:]}))
        return 1

    sys.path.insert(0, str(install_dir))
    for module in top_level_modules(wheel_path):
        try:
            runpy.run_module(module, run_name="__pypi_ai_probe__")
        except Exception as exc:
            telemetry["import_events"].append(
                {"event": "import-probe-error", "module": module, "error": str(exc)[:200]}
            )
    print(json.dumps(telemetry))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
