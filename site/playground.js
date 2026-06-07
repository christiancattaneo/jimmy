import { lintSqlText } from "./jimmy-lint.js";

const SEV = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e", info: "#8b8b96" };
const ta = document.getElementById("sql");
const out = document.getElementById("out");
const counts = document.getElementById("counts");

function escapeHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function run() {
  let findings = [];
  try {
    findings = lintSqlText(ta.value, "playground.sql");
  } catch {
    out.innerHTML = "<p>parse error</p>";
    return;
  }
  const order = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  findings.sort((a, b) => order[b.severity] - order[a.severity]);
  const tally = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) tally[f.severity]++;
  counts.innerHTML = Object.keys(SEV)
    .map((s) => `<span style="color:${SEV[s]}">${s}: ${tally[s]}</span>`)
    .join("");
  if (findings.length === 0) {
    out.innerHTML = '<p class="clean">No findings. This migration looks safe.</p>';
    return;
  }
  out.innerHTML = findings
    .map(
      (f) => `
      <div class="finding" style="--c:${SEV[f.severity]}">
        <h4><span class="badge" style="background:${SEV[f.severity]}">${f.severity}</span> ${escapeHtml(f.title)}</h4>
        <span class="rid">${escapeHtml(f.ruleId)}${f.location.line ? " &middot; line " + f.location.line : ""}</span>
        <p>${escapeHtml(f.description)}</p>
      </div>`,
    )
    .join("");
}

ta.addEventListener("input", run);
run();
