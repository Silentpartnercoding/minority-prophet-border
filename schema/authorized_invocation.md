# Authorized invocation (Mandate) relation v1

Border's existing `authority_receipt` represents one delegated authority path.
It remains unchanged.

The optional Mandate adapter represents a different relationship: Agent A is
authorized to request one exact action, while Agent B is independently
authorized to execute it. A's signed request transfers no authority to B.

```text
workspace owner -> A: may request archive_page
A -------------> B: signed MANDATE for one exact Notion page
Notion admin ---> B: may execute archive_page
B -------------> Gate -> Notion
```

The adapter emits `border-authority-relation/v1` only after verifying:

- the artifact explicitly declares `MANDATE`, not `DELEGATE`;
- A's verified authority binds A's identity/key/request and permits requesting
  the exact candidate action;
- B's separately verified authority permits executing the exact action;
- B's live credential binds B's identity/key, execution authority, action,
  audience, and time window;
- the Mandate binds A, B, the exact action digest, audience, request-authority
  receipt, time window, nonce, and signature;
- the Mandate's validity is contained within both authority paths.

The receipt contains only digests and stable identifiers and is stamped with
Border's existing DSSE/in-toto envelope. A downstream Gate verifies that
standard envelope, recomputes every digest from the original artifacts,
supplies its own expected audience, and checks that the Mandate plus both
authority paths remain current.
No receipt field is allowed to select its own verifier or policy.

The reference adapter's nonce registry is process-local. A deployment that
requires replay protection across restarts or replicas must provide durable,
atomic nonce consumption at or before its Gate; a valid receipt alone does not
establish that infrastructure property.

## Notion example

A workflow agent is allowed to request archival of `notion:page:123`. B is a
foreign runtime with independently issued Notion permission to archive that
page. A signs an exact Mandate for `archive_page`, including the page target
and payload digest. Border verifies both paths and emits one portable relation
receipt. Gate proceeds only while the receipt, request authority, executor
authority, B credential, and Mandate all remain valid.

If B can archive pages but A cannot request this archive, Border fails closed.
If A can request it but B cannot execute it, Border also fails closed.
