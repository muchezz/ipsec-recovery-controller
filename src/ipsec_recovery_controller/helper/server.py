"""Socket-activated broker: one peer UID and one bounded child at a time."""
from __future__ import annotations

import argparse
import json
import os
import pwd
import selectors
import signal
import socket
import struct
import subprocess
import time

from ipsec_recovery_controller.gateway.ssh import InspectionError

STDOUT_LIMIT = 2_000_000
STDERR_LIMIT = 65_536
COMMAND_TIMEOUT = 10
REQUEST_TIMEOUT = 2
RESPONSE_LIMIT = STDOUT_LIMIT * 6 + 1024


def peer_uid(connection: socket.socket) -> int:
    credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    return struct.unpack("3i", credentials)[1]


def command(argv: list[str]) -> str:
    """No caller-controlled executable, argv, environment, or working directory."""
    try:
        process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
            close_fds=True, cwd="/", env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    except OSError as exc:
        raise InspectionError("helper_start_failed") from exc
    output = [bytearray(), bytearray()]
    deadline = time.monotonic() + COMMAND_TIMEOUT
    try:
        with selectors.DefaultSelector() as selector:
            for index, stream in enumerate((process.stdout, process.stderr)):
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
                    limit = STDOUT_LIMIT if key.data == 0 else STDERR_LIMIT
                    if len(output[key.data]) + len(chunk) > limit:
                        raise InspectionError("output_limit")
                    output[key.data].extend(chunk)
        process.wait(timeout=max(0, deadline - time.monotonic()))
        if process.returncode:
            raise InspectionError("helper_command_failed")
        return output[0].decode("utf-8")
    except subprocess.TimeoutExpired as exc:
        raise InspectionError("timeout") from exc
    except UnicodeDecodeError as exc:
        raise InspectionError("malformed_output") from exc
    except OSError as exc:
        raise InspectionError("helper_io_failed") from exc
    finally:
        # Also kill descendants of the ipsec wrapper, including on normal exit.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()


def statusall() -> str:
    return command(["/usr/sbin/ipsec", "statusall"])


def handle(connection: socket.socket, allowed_uid: int, recovery_config=None) -> None:
    """Read one small EOF-framed request; untrusted input never reaches argv."""
    try:
        if peer_uid(connection) != allowed_uid:
            raise InspectionError("helper_unauthorized")
        request = bytearray()
        deadline = time.monotonic() + REQUEST_TIMEOUT
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise InspectionError("helper_request_timeout")
            connection.settimeout(remaining)
            chunk = connection.recv(32)
            if not chunk:
                break
            request.extend(chunk)
            if len(request) > (512 if recovery_config is not None else 32):
                raise InspectionError("helper_operation_not_allowed")
        if request == b"statusall\n":
            result = {"output": statusall()}
        elif recovery_config is not None:
            import re

            from ipsec_recovery_controller.helper.recovery import recover

            match = re.fullmatch(rb"initiate ([A-Za-z0-9][A-Za-z0-9_.-]{0,127}) ([a-f0-9]{64}) ([a-f0-9]{64}) ([0-9]{1,12})\n", request)
            if not match:
                raise InspectionError("helper_operation_not_allowed")
            result = {"output": recover(recovery_config, match[1].decode(), match[2].decode(), match[3].decode(), int(match[4]))}
        else:
            raise InspectionError("helper_operation_not_allowed")
    except InspectionError as exc:
        result = {"error": exc.code}
    except (OSError, TimeoutError):
        result = {"error": "helper_request_failed"}
    import logging
    logging.getLogger(__name__).info("audit_event %s", json.dumps({
        "event": "helper_request", "decision": result.get("error", "completed")
    }, sort_keys=True))
    connection.settimeout(2)
    try:
        connection.sendall(json.dumps(result).encode("utf-8"))
    except OSError:
        pass


def serve(listener: socket.socket, allowed_uid: int, recovery_config=None) -> None:
    # No threads or task queue: at most one inspection process group exists.
    while True:
        connection, _ = listener.accept()
        with connection:
            handle(connection, allowed_uid, recovery_config)


def main() -> None:
    import logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Socket-activated fixed strongSwan diagnostics")
    parser.add_argument("--agent-user", default="ipsec-agent")
    parser.add_argument("--recovery-config", help="root-owned optional recovery policy")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("helper must be started by its root systemd service")
    uid = pwd.getpwnam(args.agent_user).pw_uid
    if uid == 0:
        parser.error("agent identity must be unprivileged")
    if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1":
        parser.error("exactly one systemd listening socket is required")
    with socket.socket(fileno=3) as listener:
        if (listener.family != socket.AF_UNIX or
                listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM or
                not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)):
            parser.error("expected a listening Unix stream socket")
        recovery_config = None
        if args.recovery_config:
            from ipsec_recovery_controller.helper.recovery import load_policy
            recovery_config = load_policy(args.recovery_config)
        serve(listener, uid, recovery_config)


if __name__ == "__main__":
    main()
