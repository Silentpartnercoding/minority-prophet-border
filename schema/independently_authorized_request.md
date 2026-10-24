# Independently authorized request relation v1

Border's existing `authority_receipt` represents one delegated authority path.
It remains unchanged.

The optional request adapter represents a different relationship: Agent A (the
requester) is authorized to request one exact action, while Agent B (the
executor) is independently authorized to execute it. A's signed request
transfers no authority to B. We call this an independently authorized request
(IAR).

```text
workspace owner -> A: may request archive_page
A -------------> B: signed REQUEST for one exact Notion page
Notion admin ---> B: may execute archive_page
B -------------> Gate -> Notion
```

The adapter emits `border-authority-relation/v2` only after verifying:

- the artifact explicitly declares `REQUEST`, not `DELEGATE`;
- A's verified authority binds A's identity/key/request and permits requesting
  the exact candidate action;
- B's separately verified authority permits executing the exact action;
- B's live credential binds B's identity/key, execution authority, action,
  audience, and time window;
- the request binds A, B, the exact action digest, audience, request-authority
  receipt, time window, nonce, and signature;
- the request's validity is contained within both authority paths.

The receipt contains only digests and stable identifiers and is stamped with
Border's existing DSSE/in-toto envelope. A downstream Gate verifies that
standard envelope, recomputes every digest from the original artifacts,
supplies its own expected audience, and checks that the request plus both
authority paths remain current.
No receipt field is allowed to select its own verifier or policy.

The reference adapter's nonce registry is process-local. A deployment that
requires replay protection across restarts or replicas must provide durable,
atomic nonce consumption at or before its Gate; a valid receipt alone does not
establish that infrastructure property.

## Notion example

A workflow agent is allowed to request archival of `notion:page:123`. B is a
foreign runtime with independently issued Notion permission to archive that
page. A signs an exact request for `archive_page`, including the page target
and payload digest. Border verifies both paths and emits one portable relation
receipt. Gate proceeds only while the receipt, request authority, executor
authority, B credential, and request all remain valid.

If B can archive pages but A cannot request this archive, Border fails closed.
If A can request it but B cannot execute it, Border also fails closed.

## Terminology

Earlier versions called this relation a "Mandate" (`MANDATE`, schema
`authorized-invocation/v1`, receipt `border-authority-relation/v1` with
`mandate_digest`). It was renamed because "mandate" usually means authority
delegated by a principal, which is the opposite of this relation. The
verification rules are unchanged.
