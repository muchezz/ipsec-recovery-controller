"""Bounded, read-only local strongSwan command transport."""

from __future__ import annotations

import os
import selectors
import subprocess
import time
from pathlib import Path
from typing import ClassVar

from ipsec_recovery_controller.gateway.ssh import InspectionError


class LocalTransport:
    COMMANDS: ClassVar[dict[str, str]] = {"ipsec statusall": "statusall", "ipsec status": "status"}
    STDOUT_LIMIT = 2_000_000
    STDERR_LIMIT = 65_536

    def __init__(self, binary: str = "/usr/sbin/ipsec", timeout_seconds: float = 10):
        path = Path(binary)
        resolved = path.resolve()
        trusted_directories = {Path(p) for p in (
            "/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/lib/ipsec", "/usr/libexec/ipsec",
        )}
        if (not path.is_absolute() or path.name != "ipsec" or
                resolved.parent not in trusted_directories or
                resolved.name != "ipsec"):
            raise ValueError("ipsec binary must resolve to a trusted system ipsec executable")
        self.binary = str(resolved)
        self.timeout_seconds = timeout_seconds

    def run(self, gateway: object, command: str) -> str:
        argument = self.COMMANDS.get(command)
        if argument is None:
            raise InspectionError("command_not_allowed")
        try:
            process = subprocess.Popen(
                [self.binary, argument], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
            )
        except OSError as exc:
            raise InspectionError("local_start_failed") from exc
        streams = (process.stdout, process.stderr)
        output = [bytearray(), bytearray()]
        deadline = time.monotonic() + self.timeout_seconds
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
            process.wait(timeout=remaining)
        except (OSError, subprocess.TimeoutExpired, InspectionError) as exc:
            process.kill()
            process.wait()
            if isinstance(exc, InspectionError):
                raise
            raise InspectionError("timeout" if isinstance(exc, subprocess.TimeoutExpired)
                                  else "local_io_failed") from exc
        finally:
            for stream in streams:
                if stream is not None:
                    stream.close()
        if process.returncode:
            raise InspectionError("local_command_failed")
        try:
            return output[0].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InspectionError("malformed_output") from exc
