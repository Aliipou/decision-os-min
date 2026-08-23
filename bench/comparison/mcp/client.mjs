import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

const here = dirname(fileURLToPath(import.meta.url));
const scenarios = JSON.parse(
  await readFile(join(here, "..", "scenarios.json"), "utf8"),
);
const iterations = Number.parseInt(process.env.COMPARISON_ITERATIONS ?? "100", 10);
const client = new Client({ name: "decision-os-comparison-client", version: "1.0.0" });
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [join(here, "server.mjs")],
  stderr: "pipe",
});

await client.connect(transport);

async function call(scenario) {
  return client.callTool({ name: "propose_effect", arguments: scenario });
}

const rows = [];
for (const scenario of scenarios) {
  const first = await call(scenario);
  const content = first.content?.find((item) => item.type === "text");
  const response = content ? JSON.parse(content.text) : {};
  const samples = [];
  for (let i = 0; i < iterations; i += 1) {
    const start = performance.now();
    await call(scenario);
    samples.push((performance.now() - start) * 1000);
  }
  rows.push({
    id: scenario.id,
    transported: response.transported === true,
    handler_executed: response.handler_executed === true,
    samples_us: samples,
  });
}

await client.close();
process.stdout.write(`${JSON.stringify({ implementation: "official-mcp-sdk", rows })}\n`);
