# TRACEWEAVER: file-role=release-owner; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
"""Bounded Unix socket transport; authenticated Linux peer precedes JSON dispatch."""

import os
import socket
import stat
import struct

from .release_broker import (
    MAX_REQUEST,
    MAX_RESPONSE,
    SOCKET_PATH,
    BrokerError,
    authorize_peer,
    canonical,
    parse_request,
)


def response(broker, raw, uid):
    try:
        broker._reload_policy()
        authorize_peer(uid, broker.policy.get("allowed_uids"))
        request = parse_request(raw)
        actor = request["actor"]
        # A native actor is always derived from SO_PEERCRED, never client asserted.
        if actor["kind"] == "host-peer":
            actor = {"kind": "host-peer", "uid": uid}
        result = broker.dispatch(request["action"], request["params"], actor=actor)
        value = {"schema_version": 1, "ok": True, "result": result}
    except PermissionError:
        value = {
            "schema_version": 1,
            "ok": False,
            "error": {
                "code": "forbidden",
                "message": "Release peer is not authorized",
                "status": 403,
            },
        }
    except BrokerError as error:
        value = {
            "schema_version": 1,
            "ok": False,
            "error": {"code": error.code, "message": str(error), "status": error.status},
        }
    except (ValueError, TypeError):
        value = {
            "schema_version": 1,
            "ok": False,
            "error": {
                "code": "invalid-request",
                "message": "Invalid release request",
                "status": 400,
            },
        }
    except (OSError, RuntimeError, ImportError, KeyError):
        value = {
            "schema_version": 1,
            "ok": False,
            "error": {
                "code": "unavailable",
                "message": "Installed release owner is unavailable",
                "status": 503,
            },
        }
    data = canonical(value) + b"\n"
    if len(data) > MAX_RESPONSE:
        return (
            canonical(
                {
                    "schema_version": 1,
                    "ok": False,
                    "error": {
                        "code": "unavailable",
                        "message": "Release response exceeds limit",
                        "status": 503,
                    },
                }
            )
            + b"\n"
        )
    return data


# TRACEWEAVER: entrypoint=serve_connection; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
def serve_connection(connection, broker):
    connection.settimeout(3)
    try:
        credentials = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        )
        _, uid, _ = struct.unpack("3i", credentials)
        broker._reload_policy()
        authorize_peer(uid, broker.policy.get("allowed_uids"))
        raw = bytearray()
        while True:
            part = connection.recv(min(4096, MAX_REQUEST + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
            if len(raw) > MAX_REQUEST:
                raise ValueError("oversize frame")
        connection.sendall(response(broker, bytes(raw), uid))
    except (OSError, ValueError, PermissionError):
        # Transport denial exposes no parser, policy or private recovery information.
        try:
            connection.sendall(
                canonical(
                    {
                        "schema_version": 1,
                        "ok": False,
                        "error": {
                            "code": "invalid-transport",
                            "message": "Release connection refused",
                            "status": 403,
                        },
                    }
                )
                + b"\n"
            )
        except OSError:
            pass
    finally:
        connection.close()


def serve(broker):
    if os.geteuid() != 0 or not hasattr(socket, "SO_PEERCRED"):
        raise RuntimeError("release broker requires installed Linux root owner")
    if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1":
        raise RuntimeError("release broker requires fixed systemd socket activation")
    info = os.lstat(SOCKET_PATH)
    if (
        not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise PermissionError("release socket custody is invalid")
    listener = socket.socket(fileno=3)
    if listener.family != socket.AF_UNIX or listener.getsockname() != SOCKET_PATH:
        raise PermissionError("release listener identity is invalid")
    broker.reconcile()
    # Short bounded parse plus queued owner work; no request executes a command.
    while True:
        connection, _ = listener.accept()
        serve_connection(connection, broker)


def request(action, params):
    """Native root CLI shares the exact socket dispatcher and request validation."""
    from .release_broker import validate_params

    validate_params(action, params)
    value = {
        "schema_version": 1,
        "action": action,
        "params": params,
        "actor": {"kind": "host-peer", "uid": os.geteuid()},
    }
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(3)
        connection.connect(SOCKET_PATH)
        connection.sendall(canonical(value) + b"\n")
        connection.shutdown(socket.SHUT_WR)
        connection.settimeout(15)
        data = bytearray()
        while True:
            chunk = connection.recv(min(65536, MAX_RESPONSE + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > MAX_RESPONSE:
                raise RuntimeError("release response exceeds limit")
    from .release_catalog import _json

    response = _json(bytes(data))
    if response.get("schema_version") != 1 or response.get("ok") is not True:
        error = response.get("error", {})
        raise BrokerError(
            error.get("code", "unavailable"),
            error.get("message", "Release owner unavailable"),
            error.get("status", 503),
        )
    return response["result"]
