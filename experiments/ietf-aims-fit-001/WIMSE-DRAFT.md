# WIMSE adoption response — sent 2026-08-22

Subject: Re: Call for Adoption: AI Agent Authentication and Authorization

I support adoption of draft-klrc-aiagent-auth-03.

I ran a bounded fit check against two executable authorization cases that
predate this adoption call. This is not a proposal for a competing identity
protocol; the question was whether the AIMS composition can preserve the cases'
existing semantics.

This complements the request-scoped composition and cross-context splicing
concerns already raised on the list. The narrower addition here is a
non-delegating two-authority relationship plus executable A2A-to-MCP negative
vectors, rather than another conceptual framework. It also provides a concrete
case for the intermediary guidance requested in AIMS issue #65; I am not
proposing a duplicate issue.

Crosswalk and frozen evidence:
https://github.com/Silentpartnercoding/minority-prophet-border/tree/agent/ietf-aims-fit-001/experiments/ietf-aims-fit-001

The first case distinguishes an agent authorized to request one exact action
from a second agent independently authorized to execute it. The request is a
signed MANDATE and transfers no authority. AIMS can represent both agents and
their own authorization tokens, but I could not identify a pinned primitive
that represents the non-delegating relation. RFC 8693 `act` and `may_act`, and
the delegated `sub` model, would assert a different relationship.

The second case binds an authenticated A2A caller and task/context to one exact
MCP tool and argument set. Ordinary component checks admitted five substitutions
in the frozen baseline; an exact crossing binding refused four by binding alone.
Replay additionally required durable shared nonce state, which the transport
rerun showed the reference verifier did not have. AIMS/WPT/Transaction Tokens
provide strong component primitives, but I could not identify a profile that
defines the A2A-task-to-MCP-action mapping or keeps the non-delegating original
requester distinct from a credentialed intermediary presenting downstream.

My two questions are:

1. Which AIMS or referenced primitive should represent a signed request from A
   to B when A and B have separate authority paths and no authority is delegated
   from A to B, and which verifier is expected to check both paths?
2. Across an A2A-to-MCP translation and a credentialed intermediary, which
   primitive binds the original authenticated requester, current presenter,
   task/context, exact tool/arguments, current authority, and single use at the
   execution decision?

The frozen crosswalk marks a field exact only when the pinned standard defines
both its semantics and the verifier obligation; private claims and post-hoc
audit do not count as exact. Either a clean mapping or an identified companion-
profile requirement is a useful outcome.

I am happy to contribute the compact crosswalk and executable negative vectors
to the WG or to the appropriate companion-document effort.
