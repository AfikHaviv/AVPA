const form = document.getElementById("run-form");
const btn = document.getElementById("run-btn");
const errorBox = document.getElementById("error");
const results = document.getElementById("results");
const stageEls = [...document.querySelectorAll(".stage")];

const liveSection = document.getElementById("live");
const liveForm = document.getElementById("live-form");
const liveBtn = document.getElementById("live-btn");
const liveTarget = document.getElementById("live-target");
const liveLhost = document.getElementById("live-lhost");
const liveError = document.getElementById("live-error");
const liveOutput = document.getElementById("live-output");
const LIVE_CVE_IDS = JSON.parse(document.getElementById("live-cve-ids").textContent);

let currentCveId = null;

function resetStages() {
  stageEls.forEach((el) => {
    el.classList.remove("active", "done");
    el.querySelector(".timing")?.remove();
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function animateStages(stages) {
  for (const stage of stages) {
    const el = stageEls.find((e) => e.dataset.stage === stage.name);
    if (!el) continue;
    el.classList.add("active");
    await sleep(450); // brief pause so each stage is visibly "in progress"
    el.classList.remove("active");
    el.classList.add("done");
    const timing = document.createElement("span");
    timing.className = "timing";
    timing.textContent = `${stage.seconds}s`;
    el.querySelector(".label").appendChild(timing);
  }
}

function renderResults(payload) {
  const fetchStage = payload.stages.find((s) => s.name === "Fetch CVE");
  const classify = payload.stages.find((s) => s.name === "Classify CVE");
  const generate = payload.stages.find((s) => s.name === "Generate & Explain Payload (LLM)");
  const mock = payload.stages.find((s) => s.name === "Mock Execute (Simulated Target)");

  document.getElementById("out-cve").textContent = JSON.stringify(fetchStage.data.cve, null, 2);

  if (classify) {
    const c = classify.data.classification;
    document.getElementById("out-classification").textContent =
      `Category: ${c.category}\nSubtype: ${c.subtype}\nConfidence: ${c.confidence}\n` +
      `Requires user interaction: ${c.requires_user_interaction}\nMemory corruption: ${c.memory_corruption}\n` +
      (c.product_hint ? `Product: ${c.product_hint}\n` : "") +
      `\nRationale:\n${c.rationale.map((r) => `- ${r}`).join("\n")}`;
  }

  document.getElementById("out-code").textContent =
    `# FILETYPE: ${generate.data.filetype}\n` + generate.data.code;
  document.getElementById("out-breakdown").textContent = generate.data.breakdown_markdown;
  document.getElementById("out-guide").textContent = generate.data.execution_guide_markdown;

  const report = mock.data.report;
  const checksText = report.checks
    .map((c) => `[${c.passed ? "PASS" : "FAIL"}] ${c.label}`)
    .join("\n");
  const modeLine = report.mode ? `Mode: ${report.mode}\n` : "";
  const notesText = report.notes ? `\n\nNotes:\n${report.notes}` : "";
  document.getElementById("out-mock").textContent =
    `Result: ${report.success ? "SUCCESS" : "FAILED"}\n${modeLine}\n${checksText}\n\n${report.transcript.join("\n")}${notesText}`;

  results.classList.remove("hidden");
}

function updateLiveSection(cveId) {
  currentCveId = cveId;
  const supported = LIVE_CVE_IDS.includes(cveId);
  liveSection.classList.toggle("hidden", !supported);
  liveLhost.classList.toggle("hidden", cveId !== "CVE-2017-0144");
  liveLhost.required = cveId === "CVE-2017-0144";
  liveOutput.classList.add("hidden");
  liveError.classList.add("hidden");
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const cveId = document.getElementById("cve-id").value.trim();
  if (!cveId) return;

  errorBox.classList.add("hidden");
  results.classList.add("hidden");
  resetStages();
  btn.disabled = true;

  try {
    const response = await fetch("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cve_id: cveId }),
    });
    const payload = await response.json();

    if (!response.ok) {
      throw new Error(payload.error || "Pipeline failed");
    }

    await animateStages(payload.stages);
    renderResults(payload);
    updateLiveSection(payload.cve_id);
  } catch (err) {
    errorBox.textContent = err.message;
    errorBox.classList.remove("hidden");
  } finally {
    btn.disabled = false;
  }
});

liveForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!currentCveId) return;

  liveError.classList.add("hidden");
  liveOutput.classList.add("hidden");
  liveBtn.disabled = true;

  try {
    const response = await fetch("/api/execute", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        cve_id: currentCveId,
        target: liveTarget.value.trim(),
        lhost: liveLhost.value.trim(),
        confirmed: document.getElementById("live-confirmed").checked,
      }),
    });
    const payload = await response.json();

    if (!response.ok) {
      throw new Error(payload.error || "Live execution failed");
    }

    liveOutput.textContent =
      `${payload.success ? "SUCCESS" : "FAILED"}: ${payload.cve_id} against ${payload.target}\n\n` +
      payload.transcript.join("\n") +
      (payload.evidence ? `\n\nEvidence:\n${payload.evidence}` : "");
    liveOutput.classList.remove("hidden");
  } catch (err) {
    liveError.textContent = err.message;
    liveError.classList.remove("hidden");
  } finally {
    liveBtn.disabled = false;
  }
});
