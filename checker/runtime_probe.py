"""Read-only local runtime, listener, container and Compose checks."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import yaml

from .findings import Finding
from .redaction import redact_text


@dataclass
class CommandResult:
    arguments: list[str]
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and self.error is None


@dataclass
class RuntimeSnapshot:
    findings: list[Finding] = field(default_factory=list)
    evidence: dict[str, object] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


CommandRunner = Callable[[list[str], int], CommandResult]


def run_command(arguments: list[str], timeout: int = 15) -> CommandResult:
    """Run one fixed read-only command without a shell."""

    environment = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
        "NO_COLOR": "1",
    }
    try:
        result = subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CommandResult(arguments, None, error=redact_text(str(exc)))
    return CommandResult(
        arguments=arguments,
        returncode=result.returncode,
        stdout=redact_text(result.stdout[:1_048_576]),
        stderr=redact_text(result.stderr[:1_048_576]),
    )


class RuntimeProbe:
    def __init__(self, runner: CommandRunner = run_command) -> None:
        self.runner = runner

    def inspect(self, target_paths: list[Path]) -> RuntimeSnapshot:
        snapshot = RuntimeSnapshot()
        self._inspect_listeners(snapshot)
        self._inspect_docker(snapshot)
        self._inspect_runners(snapshot, target_paths)
        self._inspect_firewall(snapshot)
        self._inspect_compose(snapshot, target_paths)
        return snapshot

    def _inspect_listeners(self, snapshot: RuntimeSnapshot) -> None:
        if shutil.which("ss") is None:
            snapshot.errors.append("ss is not installed. Listener inspection was not checked.")
            return
        result = self.runner(["ss", "-H", "-lntup"], 15)
        if not result.ok:
            snapshot.errors.append(_command_error("ss", result))
            return
        listeners = parse_ss(result.stdout)
        snapshot.evidence["listeners"] = listeners
        for listener in listeners:
            if not listener["wildcard"]:
                continue
            endpoint = str(listener["local"])
            snapshot.findings.append(
                Finding(
                    layer=4,
                    severity="medium",
                    status="suspected",
                    asset=f"local listener {endpoint}",
                    title="Service listens on a wildcard address",
                    description=(
                        f"The local socket table shows {endpoint}. This may permit access from other "
                        "interfaces, but it does not establish public internet exposure."
                    ),
                    evidence=[f"ss reported {endpoint} in LISTEN state."],
                    source="runtime-probe",
                    confidence="high",
                    recommendation="Confirm the intended clients, authentication and effective firewall. Bind to loopback if remote access is unnecessary.",
                    verification="Repeat ss, container and firewall checks after an approved configuration change.",
                    risk_if_accepted="Unauthorised local-network clients may reach the service. Public exposure remains uncertain.",
                    fingerprint=f"runtime|listener|{endpoint}",
                )
            )

    def _inspect_docker(self, snapshot: RuntimeSnapshot) -> None:
        if shutil.which("docker") is None:
            snapshot.errors.append("Docker is not installed. Container exposure was not checked.")
            return
        ps = self.runner(
            ["docker", "ps", "--no-trunc", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Ports}}"],
            20,
        )
        if not ps.ok:
            snapshot.errors.append(_command_error("docker ps", ps))
            return
        containers: list[dict[str, object]] = []
        for line in ps.stdout.splitlines():
            parts = line.split("\t", 3)
            if len(parts) < 3:
                continue
            container_id, name, image = parts[:3]
            ports_text = parts[3] if len(parts) == 4 else ""
            record: dict[str, object] = {
                "id": container_id[:12],
                "name": name,
                "image": image,
                "ports_summary": ports_text,
            }
            ports = self.runner(
                ["docker", "inspect", "--format", "{{json .NetworkSettings.Ports}}", container_id],
                15,
            )
            mode = self.runner(
                ["docker", "inspect", "--format", "{{json .HostConfig.NetworkMode}}", container_id],
                15,
            )
            binds = self.runner(
                ["docker", "inspect", "--format", "{{json .HostConfig.Binds}}", container_id],
                15,
            )
            if ports.ok:
                record["ports"] = _json_or_none(ports.stdout)
                self._docker_port_findings(snapshot, name, record["ports"])
            if mode.ok:
                record["network_mode"] = _json_or_none(mode.stdout)
                if record["network_mode"] == "host":
                    snapshot.findings.append(_host_network_finding(f"container {name}"))
            if binds.ok:
                record["binds"] = _json_or_none(binds.stdout)
                if any(
                    "/var/run/docker.sock" in str(item)
                    for item in (record["binds"] if isinstance(record["binds"], list) else [])
                ):
                    snapshot.findings.append(_docker_socket_finding(f"container {name}"))
            containers.append(record)
        snapshot.evidence["containers"] = containers

    def _docker_port_findings(self, snapshot: RuntimeSnapshot, name: str, value: object) -> None:
        if not isinstance(value, dict):
            return
        for container_port, bindings in value.items():
            if not isinstance(bindings, list):
                continue
            for binding in bindings:
                if not isinstance(binding, dict):
                    continue
                host_ip = str(binding.get("HostIp") or "")
                host_port = str(binding.get("HostPort") or "")
                if host_ip not in {"", "0.0.0.0", "::"}:
                    continue
                endpoint = f"{host_ip or 'all interfaces'}:{host_port} to {container_port}"
                snapshot.findings.append(
                    Finding(
                        layer=4,
                        severity="medium",
                        status="suspected",
                        asset=f"container {name}",
                        title="Docker publishes a port on all interfaces",
                        description=(
                            f"Docker reports {endpoint}. The binding may permit network access, but "
                            "router and firewall exposure have not been established."
                        ),
                        evidence=[f"docker inspect reported {endpoint}."],
                        source="runtime-probe",
                        confidence="high",
                        recommendation="Bind the port to loopback or require an authenticated, restricted network path.",
                        verification="Repeat docker inspect, ss and firewall checks after approval.",
                        risk_if_accepted="Clients on a reachable network may access the service. Public exposure remains uncertain.",
                        fingerprint=f"runtime|docker-port|{name}|{container_port}|{host_ip}|{host_port}",
                    )
                )

    def _inspect_runners(self, snapshot: RuntimeSnapshot, target_paths: list[Path]) -> None:
        runner_commands = ("ollama", "llama-server", "llama", "lms", "lmstudio")
        versions: list[dict[str, str]] = []
        for command in runner_commands:
            executable = shutil.which(command)
            if not executable:
                continue
            result = self.runner([executable, "--version"], 10)
            versions.append(
                {
                    "command": command,
                    "path": executable,
                    "version": (result.stdout or result.stderr).strip()[:300]
                    if result.ok
                    else "version unavailable",
                }
            )

        processes: list[dict[str, object]] = []
        if shutil.which("ps"):
            result = self.runner(["ps", "-eo", "pid=,uid=,comm="], 15)
            if result.ok:
                for line in result.stdout.splitlines():
                    parts = line.split(None, 2)
                    if len(parts) != 3 or not parts[0].isdigit():
                        continue
                    pid, uid, command = parts
                    matched = command in runner_commands
                    cwd = _read_link(Path("/proc") / pid / "cwd")
                    if command.startswith("python") and cwd:
                        cwd_path = Path(cwd).resolve(strict=False)
                        matched = any(_within(cwd_path, target) for target in target_paths)
                    if not matched:
                        continue
                    environment_names = _environment_names(Path("/proc") / pid / "environ")
                    processes.append(
                        {
                            "pid": int(pid),
                            "uid": int(uid),
                            "command": command,
                            "executable": _read_link(Path("/proc") / pid / "exe"),
                            "working_directory": cwd,
                            "environment_names": environment_names,
                        }
                    )
            else:
                snapshot.errors.append(_command_error("ps", result))
        snapshot.evidence["runner_versions"] = versions
        snapshot.evidence["runner_processes"] = processes

        units: list[str] = []
        if shutil.which("systemctl"):
            for arguments in (
                ["systemctl", "--user", "list-units", "--type=service", "--all", "--no-legend", "--plain"],
                ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain"],
            ):
                result = self.runner(arguments, 15)
                if result.ok:
                    for line in result.stdout.splitlines():
                        if any(name in line.lower() for name in runner_commands):
                            units.append(" ".join(line.split())[:500])
        snapshot.evidence["runner_units"] = sorted(set(units))

    def _inspect_firewall(self, snapshot: RuntimeSnapshot) -> None:
        firewall: dict[str, str] = {}
        if shutil.which("ufw"):
            result = self.runner(["ufw", "status"], 15)
            if result.ok:
                match = re.search(r"(?im)^Status:\s*(\w+)", result.stdout)
                firewall["ufw"] = match.group(1).lower() if match else "status visible"
            else:
                firewall["ufw"] = "unavailable without further permission"
        if shutil.which("nft"):
            result = self.runner(["nft", "list", "ruleset"], 15)
            firewall["nftables"] = "ruleset visible" if result.ok else "ruleset unavailable"
        if not firewall:
            snapshot.errors.append("No supported firewall command was found. Effective filtering is unknown.")
        snapshot.evidence["firewall"] = firewall

    def _inspect_compose(self, snapshot: RuntimeSnapshot, target_paths: list[Path]) -> None:
        records: list[dict[str, object]] = []
        for path in _compose_files(target_paths):
            try:
                raw = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, yaml.YAMLError) as exc:
                snapshot.errors.append(f"Could not parse {path}: {redact_text(str(exc))}")
                continue
            if not isinstance(raw, dict) or not isinstance(raw.get("services"), dict):
                continue
            for service, configuration in raw["services"].items():
                if not isinstance(configuration, dict):
                    continue
                record = {
                    "file": str(path),
                    "service": str(service),
                    "ports": configuration.get("ports", []),
                    "network_mode": configuration.get("network_mode"),
                }
                records.append(record)
                if configuration.get("network_mode") == "host":
                    snapshot.findings.append(_host_network_finding(f"{path}:{service}"))
                volumes = configuration.get("volumes", [])
                if isinstance(volumes, list) and any(
                    "/var/run/docker.sock" in str(item) for item in volumes
                ):
                    snapshot.findings.append(_docker_socket_finding(f"{path}:{service}"))
                ports = configuration.get("ports", [])
                if isinstance(ports, list):
                    for port in ports:
                        host_ip, detail = _compose_binding(port)
                        if host_ip not in {None, "", "0.0.0.0", "::"}:
                            continue
                        snapshot.findings.append(
                            Finding(
                                layer=4,
                                severity="medium",
                                status="suspected",
                                asset=f"{path}:{service}",
                                title="Compose publishes a port on all interfaces",
                                description=(
                                    f"The Compose mapping {detail} has no loopback-only host address. "
                                    "Actual exposure depends on deployment and firewall state."
                                ),
                                evidence=[f"{path}: service {service}; port mapping {detail}"],
                                source="runtime-probe",
                                confidence="high",
                                recommendation="Set a loopback host address or document the required authenticated network path.",
                                verification="Inspect the deployed container, listener and firewall after an approved change.",
                                risk_if_accepted="A deployed service may accept connections from reachable network interfaces.",
                                fingerprint=f"compose|port|{path}|{service}|{detail}",
                            )
                        )
        snapshot.evidence["compose"] = records


def parse_ss(output: str) -> list[dict[str, object]]:
    listeners: list[dict[str, object]] = []
    pattern = re.compile(r"^\S+\s+\S+\s+\d+\s+\d+\s+(\S+)\s+(\S+)")
    for line in output.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        local = match.group(1)
        host = _endpoint_host(local)
        listeners.append(
            {
                "local": local,
                "peer": match.group(2),
                "wildcard": host in {"*", "0.0.0.0", "::"},
            }
        )
    return listeners


def _endpoint_host(endpoint: str) -> str:
    if endpoint.startswith("[") and "]" in endpoint:
        return endpoint[1 : endpoint.index("]")]
    if endpoint.count(":") > 1:
        host, _, _port = endpoint.rpartition(":")
        return host or "::"
    return endpoint.rsplit(":", 1)[0] if ":" in endpoint else endpoint


def _json_or_none(value: str) -> object:
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return None


def _command_error(label: str, result: CommandResult) -> str:
    detail = result.error or result.stderr.strip() or f"exit {result.returncode}"
    return f"{label} could not complete: {detail[:500]}"


def _read_link(path: Path) -> str | None:
    try:
        return str(path.resolve(strict=True))
    except OSError:
        return None


def _environment_names(path: Path) -> list[str]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    names: list[str] = []
    for item in data.split(b"\0"):
        name, separator, _value = item.partition(b"=")
        if separator and re.fullmatch(rb"[A-Za-z_][A-Za-z0-9_]{0,127}", name):
            names.append(name.decode("ascii"))
    return sorted(set(names))[:500]


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root.resolve(strict=False))
    except ValueError:
        return False
    return True


def _compose_files(target_paths: list[Path]) -> list[Path]:
    names = {"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}
    excluded = {".git", ".venv", "node_modules", "vendor", "reports"}
    found: list[Path] = []
    for target in target_paths:
        seen = 0
        for root, directories, files in os.walk(target):
            directories[:] = [name for name in directories if name not in excluded]
            seen += len(files)
            if seen > 50_000:
                break
            for name in files:
                if name not in names:
                    continue
                path = Path(root) / name
                try:
                    if path.stat().st_size <= 2 * 1_048_576:
                        found.append(path)
                except OSError:
                    continue
    return found


def _compose_binding(value: object) -> tuple[str | None, str]:
    if isinstance(value, dict):
        return str(value.get("host_ip") or ""), redact_text(json.dumps(value, sort_keys=True))
    detail = redact_text(str(value))
    text = detail.strip().strip("\"'")
    if text.startswith("[") and "]" in text:
        return text[1 : text.index("]")], detail
    parts = text.split(":")
    if len(parts) >= 3:
        return parts[0], detail
    return None, detail


def _host_network_finding(asset: str) -> Finding:
    return Finding(
        layer=4,
        severity="medium",
        status="suspected",
        asset=asset,
        title="Container uses host networking",
        description="Host networking removes Docker port isolation. Effective reachability still depends on the service bind address and firewall.",
        evidence=[f"Read-only container or Compose inspection reported network_mode=host for {asset}."],
        source="runtime-probe",
        confidence="high",
        recommendation="Use a private Docker network and explicit loopback port mapping unless host networking is required.",
        verification="Inspect the deployed network mode, socket listeners and firewall after an approved change.",
        risk_if_accepted="The container shares the host network and may expose any wildcard listener.",
        fingerprint=f"runtime|host-network|{asset}",
    )


def _docker_socket_finding(asset: str) -> Finding:
    return Finding(
        layer=5,
        severity="high",
        status="suspected",
        asset=asset,
        title="Container can access the Docker control socket",
        description="The Docker socket can allow a compromised container or agent tool to control other containers and host-mounted data.",
        evidence=[f"Read-only container or Compose inspection found a Docker socket bind for {asset}."],
        source="runtime-probe",
        confidence="high",
        recommendation="Remove the socket bind or replace it with a restricted broker that exposes only required operations.",
        verification="Inspect the deployed binds and prove required workflows operate without direct Docker socket access.",
        risk_if_accepted="Code in the container may gain broad control over Docker and host-mounted data.",
        fingerprint=f"runtime|docker-socket|{asset}",
    )
