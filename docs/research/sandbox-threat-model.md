# Docker Sandbox Threat Model

## Goal

The sandbox protects the host while collecting best-effort behavior telemetry from a
package artifact. It is not a perfect malware detonation platform. Its job is to make the
project defensible: untrusted package behavior is separated from the host, time-limited,
resource-limited, and evidence-only.

## Default Policy

```bash
docker run --rm \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=512m \
  --memory 768m \
  --cpus 1 \
  --pids-limit 256 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  -v /path/to/wheel-dir:/input:ro \
  pypi-ai-sandbox:latest \
  /input/package.whl
```

## Controls

| Control | Purpose |
|---|---|
| `--network none` | Prevent real outbound internet access by default. |
| `--read-only` | Prevent writes to the container root filesystem. |
| `--tmpfs /tmp` | Allow temporary analysis writes without persistence. |
| `--memory 768m` | Limit memory abuse. |
| `--cpus 1` | Limit CPU consumption. |
| `--pids-limit 256` | Limit process explosion. |
| `--cap-drop ALL` | Remove Linux capabilities not needed for analysis. |
| `--security-opt no-new-privileges` | Prevent privilege escalation through setuid/setgid paths. |
| read-only input mount | Prevent artifact modification and host writes. |

## Telemetry

The sandbox entrypoint uses Python audit hooks to record:

- process creation attempts
- file access attempts
- socket and DNS activity attempts
- import activity

The branch intentionally records attempted behavior. It does not need successful network
access to prove that a package attempted a network action.

## Limitations

- Python audit hooks do not observe all native-code behavior.
- Docker is required for dynamic probing; reports are partial when Docker is unavailable.
- The current sandbox imports top-level modules from wheels. Packages with complex import
  names may need manual probing.
- Network sinkhole/proxy mode is future work. The current default is no real network.

## Sources

- Docker run options: https://docs.docker.com/reference/cli/docker/container/run/
- OWASP Docker Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
