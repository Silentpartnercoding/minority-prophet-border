import { Message } from "@a2a-js/sdk";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { PaymentPayloadSchema } from "@x402/core/schemas";

let input = "";
for await (const chunk of process.stdin) input += chunk;
const cases = JSON.parse(input);
const results = cases.map(({ id, a2a, mcp, payment }) => {
  try {
    // These are the unmodified SDK admission/parsing surfaces. They establish
    // protocol validity, not owner-intent continuity.
    Message.fromJSON(a2a);
    CallToolRequestSchema.parse(mcp);
    PaymentPayloadSchema.parse(payment);
    return { id, native_observed: "accept" };
  } catch (error) {
    return { id, native_observed: "reject", native_error: error.name };
  }
});
process.stdout.write(JSON.stringify(results));
