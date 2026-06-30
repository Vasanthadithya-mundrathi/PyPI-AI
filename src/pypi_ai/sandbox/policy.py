from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DockerSandboxPolicy:
    image: str = "pypi-ai-sandbox:latest"
    network: str = "none"
    memory: str = "768m"
    cpus: str = "1"
    pids_limit: int = 256
    timeout_seconds: int = 120

    def docker_args(self) -> list[str]:
        return [
            "--rm",
            "--network",
            self.network,
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=512m",
            "--memory",
            self.memory,
            "--cpus",
            self.cpus,
            "--pids-limit",
            str(self.pids_limit),
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
        ]
