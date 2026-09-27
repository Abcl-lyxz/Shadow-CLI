import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { runInNewContext } from "node:vm";

class Node {
  constructor() {
    this.children = [];
    this.dataset = {};
    this.listeners = {};
    this.classList = { toggle() {} };
    this.textContent = "";
  }
  addEventListener(name, callback) { this.listeners[name] = callback; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  querySelectorAll() { return []; }
}

const flush = () => new Promise(resolve => setImmediate(resolve));
const hasDetail = node => node.children.some(card => card.children.some(child => child.className === "review-detail"));

test("local narrative appears only for exact digest-approved report bytes", async () => {
  const nodes = new Map();
  const getNode = id => {
    if (!nodes.has(id)) nodes.set(id, new Node());
    return nodes.get(id);
  };
  const document = {
    querySelector: selector => getNode(selector),
    createElement: () => new Node(),
  };
  const finding = {
    id: 1, status: "unverified", claim_type: "response_observation",
    source_event_id: 5, title: "Observation", asset: "fixture",
    review: { review_event_id: 7, poc_status: "not_attempted", confidence: "low" },
  };
  const fetch = async path => ({
    ok: true,
    json: async () => path === "/api/v1/runs"
      ? [{ id: "run-1", events: 0, last_at: "2026-09-27T00:00:00Z" }]
      : path.endsWith("/findings") ? [finding] : [],
  });
  runInNewContext(readFileSync(new URL("./app.js", import.meta.url), "utf8"), {
    document, fetch, crypto: webcrypto, TextDecoder, Uint8Array, Date,
    setInterval() {},
  });
  await flush();
  await flush();

  const report = {
    schema: "shadow-report-v1", run_id: "run-1",
    findings: [{ id: 1, source_event_id: 5, review_event_id: 7, detail: { title: "Reviewed observation" } }],
  };
  const original = Buffer.from(JSON.stringify(report));
  const digest = createHash("sha256").update(original).digest("hex");
  const digestInput = getNode("#review-digest");
  const fileInput = getNode("#review-file");
  digestInput.value = digest;
  const altered = Buffer.from(JSON.stringify({ ...report, findings: [{ ...report.findings[0], detail: { title: "Tampered" } }] }));
  fileInput.files = [{ size: altered.length, arrayBuffer: async () => Uint8Array.from(altered).buffer }];
  await fileInput.listeners.change();
  assert.match(getNode("#review-state").textContent, /Report bytes differ/);
  assert.equal(hasDetail(getNode("#findings")), false);

  fileInput.files = [{ size: original.length, arrayBuffer: async () => Uint8Array.from(original).buffer }];
  await fileInput.listeners.change();
  assert.match(getNode("#review-state").textContent, /matches the confirmed preview digest/);
  assert.equal(hasDetail(getNode("#findings")), true);

  digestInput.value = "0".repeat(64);
  digestInput.listeners.input();
  await flush();
  await flush();
  assert.equal(hasDetail(getNode("#findings")), false);
});
