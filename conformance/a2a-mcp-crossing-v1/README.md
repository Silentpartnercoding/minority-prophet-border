# A2A to MCP crossing conformance v1

This package lets an implementation test one narrow property without importing
Minority Prophet Border:

> Does authority received with an A2A task remain bound to the authenticated
> caller, task and context, and the exact MCP server, tool and arguments that
> execute?

It is an interoperability fixture, not a security certification and not a new
protocol. The reference implementation imports no `border` modules and uses
only the Python standard library.

## Run the reference fixture

From the repository root:

```sh
python3 conformance/a2a-mcp-crossing-v1/runner/run.py
python3 -m unittest tests.test_a2a_mcp_crossing_conformance
```

The runner writes nothing by default. Pass `--output PATH` to save a result
document conforming to `schemas/result.schema.json`.

## What is frozen

`cases-v1.json` defines the six case identifiers, mutations and expected bound
outcomes. `PROFILE.md` records its SHA-256 digest. Changing the corpus creates a
new profile version; it must not silently change v1.

The JSON files under `vectors/` are illustrative inputs for the independent
reference runner. An external implementation may translate them into its own
wire objects, but its submission must say exactly what was preserved,
transformed, dropped or non-comparable.

## What an external reproduction must replace

The local runner is intentionally not a reproduction claim. It uses fixture
objects rather than network A2A and MCP servers, and a local status document
rather than a production revocation service. A qualifying external submission
must use:

1. an independently maintained A2A implementation over its real transport;
2. an independently maintained MCP server over its real transport;
3. an effect recorder outside the crossing verifier;
4. replay attempts in separate verifier processes or instances with shared
   durable state;
5. a real authority status or revocation source; and
6. commit-pinned configuration and raw results.

See `PROFILE.md` for the normative fixture rules and `submissions/README.md` for
the evidence contract. `ADAPTER-CONTRACT.md` defines where real A2A, authority,
MCP and effect observations must come from.
