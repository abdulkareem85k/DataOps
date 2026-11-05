"""Shell-free scanner command construction and execution."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

from app.schemas import NiktoRequest, NmapRequest

NMAP_PATH = "/usr/bin/nmap"
NIKTO_PATH = "/usr/bin/nikto"
MAX_OUTPUT_CHARS = 100_000


@dataclass(frozen=True)
class CommandSpec:
    """An allowlisted fixed executable and its validated argument vector."""

    argv: tuple[str, ...]
    timeout_seconds: int


def build_nmap_command(request: NmapRequest, target: str) -> CommandSpec:
    """Build a non-script, bounded top-port/service scan with fixed options."""
    return CommandSpec(
        argv=(
            NMAP_PATH,
            "-n",
            "-Pn",
            "-sV",
            "--version-light",
            "--top-ports",
            str(request.top_ports),
            "-oX",
            "-",
            target,
        ),
        timeout_seconds=request.timeout_seconds,
    )


def build_nikto_command(request: NiktoRequest, target: str) -> CommandSpec:
    """Build a bounded web scan; the route requires an approval reference and opt-in."""
    argv = [
        NIKTO_PATH,
        "-host",
        target,
        "-port",
        str(request.port),
        "-output",
        "-",
        "-Format",
        "json",
        "-nointeractive",
    ]
    if request.use_https:
        argv.append("-ssl")
    return CommandSpec(argv=tuple(argv), timeout_seconds=request.timeout_seconds)


def execute_command(command: CommandSpec) -> tuple[int, str, str, bool]:
    """Run only the supplied fixed argument vector with shell execution disabled."""
    completed = subprocess.run(
        list(command.argv),
        check=False,
        capture_output=True,
        text=True,
        timeout=command.timeout_seconds,
        shell=False,
        cwd="/tmp",
        env={"PATH": "/usr/bin:/bin", "HOME": "/tmp", "LANG": "C.UTF-8"},
    )
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    truncated = len(stdout) > MAX_OUTPUT_CHARS or len(stderr) > MAX_OUTPUT_CHARS
    return (
        completed.returncode,
        stdout[:MAX_OUTPUT_CHARS],
        stderr[:MAX_OUTPUT_CHARS],
        truncated,
    )
