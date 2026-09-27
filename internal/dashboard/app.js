const runsNode = document.querySelector("#runs");
const eventsNode = document.querySelector("#events");
const titleNode = document.querySelector("#title");
const countNode = document.querySelector("#count");
const findingsNode = document.querySelector("#findings");
const reviewFile = document.querySelector("#review-file");
const reviewState = document.querySelector("#review-state");
let reviewedReport = null;
let activeRun = "";

async function getJSON(path) {
  const response = await fetch(path, { credentials: "same-origin" });
  if (!response.ok) throw new Error("Request failed: " + response.status);
  return (await response.json()) || [];
}

function element(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined) node.textContent = value;
  return node;
}

async function selectRun(id) {
  activeRun = id;
  for (const node of runsNode.querySelectorAll(".run")) node.classList.toggle("active", node.dataset.id === id);
  titleNode.textContent = id;
  eventsNode.replaceChildren(element("div", "muted", "Loading events…"));
  try {
    const events = await getJSON("/api/v1/runs/" + encodeURIComponent(id) + "/events");
    countNode.textContent = events.length + " events";
    eventsNode.replaceChildren();
    if (!events.length) eventsNode.append(element("div", "empty", "No events recorded."));
    for (const event of events) {
      const card = element("article", "event");
      const top = element("div", "event-top");
      top.append(element("span", "event-kind", event.kind), element("span", "", new Date(event.at).toLocaleString()));
      const payload = typeof event.payload === "object" ? event.payload : { text: event.payload };
      card.append(top, element("pre", "", payload.text || JSON.stringify(payload, null, 2)));
      eventsNode.append(card);
    }
    const findings = await getJSON("/api/v1/runs/" + encodeURIComponent(id) + "/findings");
    findingsNode.replaceChildren();
    if (!findings.length) findingsNode.append(element("div", "empty", "No findings recorded."));
    for (const finding of findings) {
      const card = element("article", "event");
      const top = element("div", "event-top");
      const label = finding.status === "verified" && finding.claim_type === "response_observation" ? "Response reproduced" : "Hypothesis";
      top.append(element("span", "event-kind", label), element("span", "", finding.asset));
      card.append(top, element("h3", "finding-title", finding.title), element("div", "finding-meta", "Source event #" + finding.source_event_id + (finding.reproduction_event_id ? " · Repeat event #" + finding.reproduction_event_id : "")));
      if (finding.review) {
        const review = finding.review;
        card.append(element("div", "finding-meta", "PoC: " + review.poc_status + " · Confidence: " + review.confidence + (review.duplicate_of ? " · Duplicate of #" + review.duplicate_of : "") + (review.cvss_vector ? " · Provisional CVSS v4: " + review.cvss_score + " (" + review.cvss_vector + ")" : "")));
      }
      const entry = reviewedReport?.run_id === id ? reviewedReport.findings.find(item => item.id === finding.id && item.source_event_id === finding.source_event_id && item.review_event_id === finding.review?.review_event_id) : null;
      if (entry?.detail) {
        const detail = element("dl", "review-detail");
        for (const [label, value] of [["Title", entry.detail.title], ["Asset", entry.detail.asset_label], ["Observed", entry.detail.observed], ["Expected", entry.detail.expected], ["Prerequisites", entry.detail.preconditions], ["Impact assessment", entry.detail.impact], ["Operator-reviewed evidence excerpt", entry.detail.evidence_excerpt], ["PoC explanation", entry.detail.poc_explanation], ["Validation plan", entry.detail.validation_plan], ["Remediation", entry.detail.remediation], ["Business priority", entry.detail.business_priority]]) {
          if (typeof value === "string" && value) detail.append(element("dt", "", label), element("dd", "", value));
        }
        card.append(detail);
      }
      findingsNode.append(card);
    }
  } catch (error) {
    eventsNode.replaceChildren(element("div", "empty", error.message));
    findingsNode.replaceChildren(element("div", "empty", error.message));
  }
}

reviewFile.addEventListener("change", async () => {
  reviewedReport = null;
  const file = reviewFile.files?.[0];
  if (!file) return;
  if (file.size > 128 * 1024) {
    reviewState.textContent = "Report exceeds 128 KiB.";
    return;
  }
  try {
    const candidate = JSON.parse(await file.text());
    if (candidate.schema !== "shadow-report-v1" || candidate.run_id !== activeRun || !Array.isArray(candidate.findings) || candidate.findings.length > 50) throw new Error("Report does not match this run.");
    reviewedReport = candidate;
    reviewState.textContent = "Local reviewed report loaded for " + activeRun + ". Check its export digest before use.";
    await selectRun(activeRun);
  } catch (error) {
    reviewState.textContent = error.message;
  }
});

async function loadRuns() {
  try {
    const runs = await getJSON("/api/v1/runs");
    runsNode.replaceChildren();
    if (!runs.length) {
      runsNode.append(element("div", "muted", "No runs yet."));
      return;
    }
    for (const run of runs) {
      const button = element("button", "run");
      button.dataset.id = run.id;
      button.append(element("strong", "", run.id), element("span", "", run.events + " events · " + new Date(run.last_at).toLocaleString()));
      button.addEventListener("click", () => selectRun(run.id));
      runsNode.append(button);
    }
    await selectRun(runs[0].id);
  } catch (error) {
    runsNode.replaceChildren(element("div", "muted", error.message));
  }
}

loadRuns();
setInterval(loadRuns, 15000);
