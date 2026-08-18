"""The two lanes of A2A-MCP-CROSSING-001.

Both lanes run the same crossing: an A2A task arrives from an authenticated
caller, and the receiving agent invokes an MCP tool. The lanes differ only in
whether a Border exact-crossing binding is rechecked before the tool runs.

  native   A2A and MCP composed directly. Each side does what its own protocol
           specifies: A2A authenticates the caller and hands the executor a
           RequestContext; MCP validates the tool name and argument schema.
           Nothing represents a binding between the two.

  bound    Identical, plus a Border authority-relation receipt carried in the
           A2A message metadata and rechecked by Gate against what is actually
           about to be invoked.

Fidelity, stated rather than assumed:

  * The A2A objects are the SDK's own. `ServerCallContext` carries the
    authenticated user exactly as transport middleware populates it, and
    `RequestContext` is the object the SDK hands to an executor.
  * The MCP server is a real `MCPServer` with a registered tool. Dispatch goes
    through `call_tool`, so argument-schema validation and unknown-tool
    rejection are the SDK's, not ours.
  * Transport is in-process. Neither lane crosses a socket. The mutations under
    test are about identity, task and argument binding, none of which the wire
    format changes -- but this is a limit of the experiment and is reported.
  * The native lane's agent does the ordinary thing: it performs the action the
    task asks for. No check is deliberately omitted. Any binding check would be
    application code that neither protocol requires.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

from a2a.auth.user import User
from a2a.server.context import ServerCallContext
from mcp.server import MCPServer

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from border.mandate_adapter import (  # noqa: E402
    MandateAdapterError,
    MandateAuthorityAdapter,
    document_digest,
)

AUDIENCE = "border-sandbox.example"
NOW = "2026-08-18T12:00:00Z"


class NamedUser(User):
    """An authenticated A2A caller, as transport auth middleware would supply."""

    def __init__(self, name: str):
        self._name = name

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def user_name(self) -> str:
        return self._name


@dataclass
class Invocation:
    """What actually reached the MCP server."""

    tool: str
    arguments: dict
    lane: str


@dataclass
class Crossing:
    """One A2A task that intends to cause one MCP tool invocation."""

    caller: str = "agent-a"
    executor: str = "agent-b"
    task_id: str = "task-1"
    context_id: str = "context-1"
    tool: str = "interop.echo"
    arguments: dict = field(default_factory=lambda: {"payload": "hello"})
    nonce: str = "crossing-nonce-0001"
    authority_is_current: bool = True

    def action(self) -> dict:
        """The exact action the crossing is about."""
        return {
            "type": self.tool,
            "target": self.task_id,
            "payload_digest": document_digest(self.arguments),
        }


def build_server(observed: list[Invocation], lane: str) -> MCPServer:
    """A real MCP server exposing the harmless echo used by the Border sandbox."""
    server = MCPServer(name="border-sandbox", version="0.1")

    @server.tool(name="interop.echo", description="Harmless echo. No side effects.")
    def echo(payload: str) -> str:
        observed.append(Invocation("interop.echo", {"payload": payload}, lane))
        return payload

    return server


def _authority_records(authorized: Crossing):
    """The two independent authority paths, bound to the authorized action."""
    action_digest = document_digest(authorized.action())
    request = {
        "receipt_id": "request-authority-1",
        "request_id": authorized.task_id,
        "subject_id": authorized.caller,
        "subject_key_thumbprint": f"thumbprint-{authorized.caller}",
        "principal_id": "workspace-owner",
        "action_digest": document_digest({
            "type": "a2a.request",
            "target": authorized.task_id,
            "payload_digest": authorized.action()["payload_digest"],
        }),
        "authorized_execution_action_digest": action_digest,
        "status": "active",
        "decision": "allow",
        "not_before": "2026-08-18T11:00:00Z",
        "expires_at": "2026-08-18T13:00:00Z",
        "issued_at": "2026-08-18T10:59:00Z",
        "key_id": "a2a-authority-key",
        "signature": "verified-request-authority",
    }
    executor = {
        "receipt_id": "executor-authority-1",
        "subject_id": authorized.executor,
        "principal_id": "mcp-tool-admin",
        "action_digest": action_digest,
        "status": "active",
        "decision": "allow",
        "not_before": "2026-08-18T11:00:00Z",
        "expires_at": "2026-08-18T13:30:00Z",
        "issued_at": "2026-08-18T10:58:00Z",
        "key_id": "mcp-authority-key",
        "signature": "verified-executor-authority",
    }
    credential = {
        "credential_id": "executor-credential-1",
        "subject_id": authorized.executor,
        "subject_key_thumbprint": f"thumbprint-{authorized.executor}",
        "authority_receipt_digest": document_digest(executor),
        "action_digest": action_digest,
        "audience": AUDIENCE,
        "status": "active",
        "not_before": "2026-08-18T11:00:00Z",
        "expires_at": "2026-08-18T12:30:00Z",
        "issued_at": "2026-08-18T10:59:30Z",
        "key_id": "agent-b-key",
        "signature": "verified-executor-credential",
    }
    mandate = {
        "schema": "authorized-invocation/v1",
        "mandate_id": "mandate-1",
        "request_id": authorized.task_id,
        "relationship": "MANDATE",
        "requester_id": authorized.caller,
        "requester_key_thumbprint": f"thumbprint-{authorized.caller}",
        "executor_id": authorized.executor,
        "executor_key_thumbprint": f"thumbprint-{authorized.executor}",
        "request_authority_receipt_digest": document_digest(request),
        "action_digest": action_digest,
        "audience": AUDIENCE,
        "not_before": "2026-08-18T11:30:00Z",
        "expires_at": "2026-08-18T12:15:00Z",
        "issued_at": "2026-08-18T11:29:00Z",
        "nonce": authorized.nonce,
        "key_id": "agent-a-key",
        "signature": "verified-mandate",
    }
    return mandate, request, executor, credential


def _context(authorized: Crossing, current: bool):
    """Verification callbacks. Signatures verify; currency is a lane input."""
    from a2a.server.context import ServerCallContext as _unused  # noqa: F401

    from border.mandate_adapter import MandateAdapterContext

    return MandateAdapterContext(
        audience=AUDIENCE,
        verify_request_authority=lambda r: r.get("signature") == "verified-request-authority",
        verify_executor_authority=lambda r: r.get("signature") == "verified-executor-authority",
        verify_executor_credential=lambda r: r.get("signature") == "verified-executor-credential",
        verify_mandate=lambda r: r.get("signature") == "verified-mandate" and current,
        request_authorizes=lambda r, a: (
            r.get("authorized_execution_action_digest") == document_digest(a)),
        executor_authorizes=lambda r, a: r.get("action_digest") == document_digest(a),
        clock=lambda: __import__("datetime").datetime.fromisoformat(
            NOW.replace("Z", "+00:00")),
    )


class CrossingAgent:
    """The A2A agent that receives a task and invokes an MCP tool.

    `bound=False` is the native lane: perform the action the task asks for.
    `bound=True` additionally rechecks a Border receipt against the invocation
    that is actually about to happen.
    """

    def __init__(self, bound: bool, authorized: Crossing, observed: list[Invocation]):
        self.bound = bound
        self.authorized = authorized
        self.lane = "bound" if bound else "native"
        self.server = build_server(observed, self.lane)
        self._seen_nonces: set[str] = set()

    async def handle(self, call_context: ServerCallContext, presented: Crossing) -> str:
        """Handle one A2A task. Returns the tool result, or raises."""
        caller = call_context.user.user_name

        if self.bound:
            self._recheck(caller, presented)

        result = await self.server.call_tool(presented.tool, presented.arguments)
        return result.content[0].text

    def _recheck(self, caller: str, presented: Crossing) -> None:
        """Gate-side recheck: does the receipt bind what is about to run?"""
        mandate, request, executor, credential = _authority_records(self.authorized)

        if not presented.authority_is_current:
            raise MandateAdapterError(
                "mandate is revoked, stale, or indeterminate at Gate decision")
        if presented.nonce in self._seen_nonces:
            raise MandateAdapterError("nonce replay")
        if caller != mandate["requester_id"]:
            raise MandateAdapterError(
                f"requester identity substitution: receipt binds "
                f"{mandate['requester_id']}, task presented by {caller}")
        if presented.task_id != mandate["request_id"]:
            raise MandateAdapterError(
                f"request_id substitution: receipt binds {mandate['request_id']}, "
                f"task presented as {presented.task_id}")

        # The exact action about to be invoked, not the one that was promised.
        adapter = MandateAuthorityAdapter(
            _context(self.authorized, presented.authority_is_current))
        adapter.normalize(mandate, request, executor, credential, presented.action())
        self._seen_nonces.add(presented.nonce)
