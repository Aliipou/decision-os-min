import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import * as z from "zod/v4";

serveStdio(() => {
  const server = new McpServer(
    { name: "decision-os-comparison", version: "1.0.0" },
    { capabilities: { tools: {} } },
  );

  server.registerTool(
    "propose_effect",
    {
      description: "Transport a structurally valid agent effect proposal.",
      inputSchema: z.object({
        id: z.string(),
        actor: z.string(),
        tool: z.string(),
        capability: z.string(),
        purpose: z.string(),
        data_label: z.string(),
        consent: z.boolean(),
        expected: z.enum(["ALLOW", "DENY"]),
      }),
      annotations: {
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async (proposal) => ({
      content: [
        {
          type: "text",
          text: JSON.stringify({
            transported: true,
            handler_executed: true,
            scenario_id: proposal.id,
          }),
        },
      ],
    }),
  );
  return server;
});
