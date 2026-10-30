"""Bounded, fixed-command SSH transport for strongSwan diagnostics."""

from __future__ import annotations

import os
import selectors
import subprocess
import time
from typing import Protocol

from ipsec_recovery_controller.config import Gateway


class InspectionError(Exception):
    """Structured inspection failure safe to expose as a code, not raw SSH output."""

    def __init__(self, code: str, message: str | None = None):
        self.code = code
        super().__init__(message or code)


class GatewayTransport(Protocol):
    def run(self, gateway: Gateway, command: str) -> str: ...


class SSHTransport:
    """Run only allowlisted diagnostic commands with strict host-key checking."""

    COMMANDS = frozenset({"ipsec statusall", "ipsec status"})
    STDOUT_LIMIT = 2_000_000
    STDERR_LIMIT = 65_536

    def run(self, gateway: Gateway, command: str) -> str:
        if command not in self.COMMANDS:
            raise InspectionError("command_not_allowed")
        args = [
            "ssh", "-F", "/dev/null", "-T",
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "IdentitiesOnly=yes", "-o", "ClearAllForwardings=yes",
            "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
            "-o", "ControlMaster=no", "-o", "ControlPath=none",
            "-o", "ControlPersist=no", "-o", "ProxyCommand=none",
            "-o", "PermitLocalCommand=no", "-o", "UpdateHostKeys=no",
            "-o", f"ConnectTimeout={gateway.ssh_timeout_seconds}",
            "-p", str(gateway.ssh_port),
        ]
        if gateway.ssh_identity_file:
            args.extend(["-i", gateway.ssh_identity_file])
        if gateway.ssh_known_hosts_file:
            args.extend(["-o", f"UserKnownHostsFile={gateway.ssh_known_hosts_file}"])
        args.extend(["--", f"{gateway.ssh_user}@{gateway.host}", command])
        try:
            process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as exc:
            raise InspectionError("ssh_start_failed") from exc
        streams = (process.stdout, process.stderr)
        assert all(stream is not None for stream in streams)
        output = [bytearray(), bytearray()]
        deadline = time.monotonic() + gateway.ssh_timeout_seconds + 5
        try:
            with selectors.DefaultSelector() as selector:
                for index, stream in enumerate(streams):
                    assert stream is not None
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, index)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise InspectionError("timeout")
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        index = key.data
                        limit = self.STDOUT_LIMIT if index == 0 else self.STDERR_LIMIT
                        if len(output[index]) + len(chunk) > limit:
                            raise InspectionError("output_limit")
                        output[index].extend(chunk)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise InspectionError("timeout")
            try:
                returncode = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                raise InspectionError("timeout") from exc
        except (OSError, InspectionError) as exc:
            process.kill()
            process.wait()
            if isinstance(exc, InspectionError):
                raise
            raise InspectionError("ssh_io_failed") from exc
        finally:
            for stream in streams:
                if stream is not None:
                    stream.close()
        if returncode != 0:
            stderr = output[1].decode("utf-8", errors="replace")
            if "Permission denied" in stderr:
                code = "authentication_failed"
            elif "Host key verification failed" in stderr or "REMOTE HOST IDENTIFICATION HAS CHANGED" in stderr:
                code = "host_key_failed"
            else:
                code = "ssh_command_failed"
            raise InspectionError(code)
        try:
            return output[0].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InspectionError("malformed_output", "diagnostic output is not UTF-8") from exc
