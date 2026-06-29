const severityOrder = ["critical", "high", "medium", "low", "info"];

const state = {
  report: null,
  status: null,
  search: "",
  severity: "all",
  category: "all",
  packageName: "all",
  selectedId: "",
};

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => {
    const entities = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    };
    return entities[character];
  });
}

function safeClass(value, fallback = "review") {
  const text = String(value || "");
  return /^[a-z0-9_-]+$/i.test(text) ? text : fallback;
}

const elements = {
  rows: document.querySelector("#evidenceRows"),
  rowCount: document.querySelector("#rowCount"),
  filteredCount: document.querySelector("#filteredCount"),
  filteredHint: document.querySelector("#filteredHint"),
  severityFilters: document.querySelector("#severityFilters"),
  categoryFilter: document.querySelector("#categoryFilter"),
  packageFilter: document.querySelector("#packageFilter"),
  searchBox: document.querySelector("#searchBox"),
  reportFile: document.querySelector("#reportFile"),
  statusFile: document.querySelector("#statusFile"),
  detailMeta: document.querySelector("#detailMeta"),
  detailSnippet: document.querySelector("#detailSnippet"),
  detailNotes: document.querySelector("#detailNotes"),
  detailCitations: document.querySelector("#detailCitations"),
  barChart: document.querySelector("#barChart"),
  trendChart: document.querySelector("#trendChart"),
  installList: document.querySelector("#installList"),
  providerList: document.querySelector("#providerList"),
  reportList: document.querySelector("#reportList"),
  branchList: document.querySelector("#branchList"),
  qualityList: document.querySelector("#qualityList"),
  osvList: document.querySelector("#osvList"),
  debugGrid: document.querySelector("#debugGrid"),
  totalScans: document.querySelector("#totalScans"),
  scanSource: document.querySelector("#scanSource"),
  packagesScanned: document.querySelector("#packagesScanned"),
  inputType: document.querySelector("#inputType"),
  riskScore: document.querySelector("#riskScore"),
  riskLevel: document.querySelector("#riskLevel"),
  osvCacheHits: document.querySelector("#osvCacheHits"),
  osvHint: document.querySelector("#osvHint"),
  verifiedInstalls: document.querySelector("#verifiedInstalls"),
  installHint: document.querySelector("#installHint"),
  aiProvider: document.querySelector("#aiProvider"),
  aiProviderHint: document.querySelector("#aiProviderHint"),
  targetValue: document.querySelector("#targetValue"),
  targetType: document.querySelector("#targetType"),
  filesScanned: document.querySelector("#filesScanned"),
  scanPackages: document.querySelector("#scanPackages"),
  trendWindow: document.querySelector("#trendWindow"),
  ruleTrace: document.querySelector("#ruleTrace"),
  scanPlan: document.querySelector("#scanPlan"),
  providerFallback: document.querySelector("#providerFallback"),
};

async function loadJson(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`${path}: ${response.status}`);
  }
  return response.json();
}

function normalizeFindings(report) {
  return (report?.findings || []).map((finding) => ({
    id: finding.finding_id,
    packageName: finding.package_name || report?.summary?.target || "unknown",
    version: finding.package_version || "-",
    severity: severityOrder.includes(String(finding.severity || "").toLowerCase())
      ? String(finding.severity).toLowerCase()
      : "info",
    rule: finding.rule_id || "-",
    category: finding.category || "-",
    file: finding.file_path || "-",
    line: finding.line_start || "-",
    confidence: Math.round((finding.confidence || 0) * 100),
    citations: finding.citations || [],
    message: finding.message || "",
    snippet: finding.snippet || "",
    notes: `${finding.message || "Finding recorded."} [${finding.finding_id}]`,
    tags: finding.tags || [],
  }));
}

function unique(values) {
  return Array.from(new Set(values)).filter(Boolean).sort();
}

function setText(idOrElement, value) {
  const element = typeof idOrElement === "string" ? document.querySelector(idOrElement) : idOrElement;
  if (element) {
    element.textContent = value;
  }
}

function filteredFindings() {
  const findings = normalizeFindings(state.report);
  return findings.filter((finding) => {
    const text = [
      finding.id,
      finding.packageName,
      finding.rule,
      finding.category,
      finding.file,
      finding.message,
    ]
      .join(" ")
      .toLowerCase();
    return (
      text.includes(state.search.toLowerCase()) &&
      (state.severity === "all" || finding.severity === state.severity) &&
      (state.category === "all" || finding.category === state.category) &&
      (state.packageName === "all" || finding.packageName === state.packageName)
    );
  });
}

function resetSelect(select, label, values) {
  select.innerHTML = `<option value="all">${label}</option>`;
  values.forEach((value) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value;
    select.appendChild(option);
  });
}

function renderFilters() {
  elements.severityFilters.innerHTML = "";
  ["all", ...severityOrder].forEach((severity) => {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = severity.toUpperCase();
    button.className = state.severity === severity ? "active" : "";
    button.addEventListener("click", () => {
      state.severity = severity;
      render();
    });
    elements.severityFilters.appendChild(button);
  });

  const findings = normalizeFindings(state.report);
  resetSelect(elements.categoryFilter, "all categories", unique(findings.map((item) => item.category)));
  resetSelect(elements.packageFilter, "all packages", unique(findings.map((item) => item.packageName)));
  elements.categoryFilter.value = state.category;
  elements.packageFilter.value = state.packageName;
}

function renderSummary(items) {
  const summary = state.report?.summary || {};
  const risk = state.report?.risk || {};
  setText(elements.totalScans, state.report ? "1" : "-");
  setText(elements.scanSource, state.report ? "loaded report" : "load report JSON");
  setText(elements.packagesScanned, summary.packages_scanned ?? "-");
  setText(elements.inputType, summary.input_type || "not loaded");
  setText(elements.filteredCount, String(items.length));
  setText(elements.filteredHint, `of ${normalizeFindings(state.report).length} total`);
  setText(elements.riskScore, risk.score ?? "-");
  setText(elements.riskLevel, risk.level ? `level: ${risk.level}` : "not loaded");
  setText(elements.targetValue, summary.target || "not loaded");
  setText(elements.targetType, summary.input_type || "not loaded");
  setText(elements.filesScanned, summary.files_scanned ?? 0);
  setText(elements.scanPackages, summary.packages_scanned ?? 0);
  setText(elements.trendWindow, state.report ? "single loaded report" : "not loaded");
  setText(elements.rowCount, `${items.length} rows`);
}

function renderRows(items) {
  elements.rows.innerHTML = "";
  if (!items.length) {
    elements.rows.innerHTML =
      '<tr><td colspan="11">No findings loaded. Load a PyPi-AI JSON report to populate this table.</td></tr>';
    return;
  }
  items.forEach((finding) => {
    const row = document.createElement("tr");
    row.className = finding.id === state.selectedId ? "selected" : "";
    row.addEventListener("click", () => {
      state.selectedId = finding.id;
      render();
    });
    row.innerHTML = `
      <td>${escapeHtml(finding.id)}</td>
      <td>${escapeHtml(finding.packageName)}</td>
      <td>${escapeHtml(finding.version)}</td>
      <td><span class="severity ${finding.severity}">${finding.severity.toUpperCase()}</span></td>
      <td>${escapeHtml(finding.rule)}</td>
      <td>${escapeHtml(finding.category)}</td>
      <td>${escapeHtml(finding.file)}</td>
      <td>${escapeHtml(finding.line)}</td>
      <td>${finding.confidence}%</td>
      <td>${finding.citations.length}</td>
      <td class="message-cell">${escapeHtml(finding.message)}</td>
    `;
    elements.rows.appendChild(row);
  });
}

function renderDetail(items) {
  const selected = items.find((finding) => finding.id === state.selectedId) || items[0];
  if (!selected) {
    elements.detailMeta.innerHTML = "<div><dt>Status</dt><dd>No finding selected</dd></div>";
    elements.detailSnippet.textContent = "Load a PyPi-AI JSON report.";
    elements.detailNotes.textContent = "The dashboard only displays loaded PyPi-AI report findings.";
    elements.detailCitations.textContent = "";
    return;
  }
  state.selectedId = selected.id;
  elements.detailMeta.innerHTML = `
    <div><dt>Evidence ID</dt><dd>${escapeHtml(selected.id)}</dd></div>
    <div><dt>Rule</dt><dd>${escapeHtml(selected.rule)}</dd></div>
    <div><dt>Package</dt><dd>${escapeHtml(selected.packageName)} ${escapeHtml(selected.version)}</dd></div>
    <div><dt>File / Line</dt><dd>${escapeHtml(selected.file)}:${escapeHtml(selected.line)}</dd></div>
    <div><dt>Confidence</dt><dd>${selected.confidence}%</dd></div>
    <div><dt>Category</dt><dd>${escapeHtml(selected.category)}</dd></div>
  `;
  elements.detailSnippet.textContent = selected.snippet || "No snippet recorded.";
  elements.detailNotes.textContent = selected.notes;
  elements.detailCitations.textContent = `Tags: ${selected.tags.join(", ") || "none"}. Citations: ${
    selected.citations.join(", ") || "none"
  }.`;
}

function renderBars() {
  const findings = normalizeFindings(state.report);
  const counts = Object.fromEntries(severityOrder.map((severity) => [severity, 0]));
  findings.forEach((finding) => {
    counts[finding.severity] = (counts[finding.severity] || 0) + 1;
  });
  const max = Math.max(...Object.values(counts), 1);
  elements.barChart.innerHTML = "";
  severityOrder.forEach((severity) => {
    const bar = document.createElement("div");
    bar.className = "bar";
    const height = counts[severity] ? Math.max(12, Math.round((counts[severity] / max) * 120)) : 4;
    bar.innerHTML = `
      <strong>${counts[severity]}</strong>
      <div class="bar-value" style="height:${height}px"></div>
      <span>${severity.slice(0, 4)}</span>
    `;
    elements.barChart.appendChild(bar);
  });
}

function renderTrend() {
  const riskScore = Number(state.report?.risk?.score ?? 0);
  const clamped = Math.max(0, Math.min(100, Number.isFinite(riskScore) ? riskScore : 0));
  const y = 140 - clamped * 1.1;
  const level = state.report?.risk?.level || "not loaded";
  if (!state.report) {
    elements.trendChart.innerHTML = '<text x="22" y="88" class="axis-label">Load a PyPi-AI report JSON</text>';
    return;
  }
  elements.trendChart.innerHTML = `
    <line class="trend-axis" x1="46" y1="30" x2="46" y2="140"></line>
    <line class="trend-axis" x1="46" y1="140" x2="486" y2="140"></line>
    <line class="trend-guide" x1="46" y1="${y}" x2="486" y2="${y}"></line>
    <circle class="trend-dot" cx="266" cy="${y}" r="7"></circle>
    <text x="16" y="34" class="axis-label">100</text>
    <text x="24" y="144" class="axis-label">0</text>
    <text x="218" y="162" class="axis-label">Loaded report</text>
    <text x="282" y="${Math.max(24, y - 10)}" class="risk-label">risk ${clamped} / ${escapeHtml(level)}</text>
  `;
}

function renderStatus() {
  const status = state.status || {};
  const install = status.verified_install || {};
  const providers = status.providers || [];
  const branches = status.branches || [];
  const reports = status.reports || [];
  const quality = status.quality_gates || [];
  const osv = status.osv || {};

  setText(elements.osvCacheHits, osv.cache_hits ?? "-");
  setText(elements.osvHint, osv.status || "not loaded");
  setText(elements.verifiedInstalls, install.summary || "-");
  setText(elements.installHint, install.status || "not loaded");
  const primaryProvider = providers.find((provider) => provider.primary) || providers[0];
  setText(elements.aiProvider, primaryProvider?.name || "-");
  setText(elements.aiProviderHint, primaryProvider?.status || "not loaded");

  elements.installList.innerHTML = install.notes
    ? `<div class="status-item"><div class="status-title"><strong>${escapeHtml(install.status)}</strong><span>${escapeHtml(install.notes)}</span></div><span class="status-badge ${safeClass(install.status_class)}">${escapeHtml(install.source || "artifact")}</span></div>`
    : '<div class="status-item"><div class="status-title"><strong>No install artifact loaded</strong><span>Load project-status.json to populate this panel.</span></div></div>';

  elements.providerList.innerHTML = providers.length
    ? providers
        .map(
          (provider) => `
        <div class="provider">
          <div class="provider-title"><strong>${escapeHtml(provider.name)}</strong><span>${escapeHtml(provider.detail)}</span></div>
          <span class="provider-state ${safeClass(provider.status_class, "ok")}">${escapeHtml(provider.status)}</span>
        </div>
      `,
        )
        .join("")
    : '<div class="provider"><div class="provider-title"><strong>No provider status loaded</strong><span>Load project-status.json.</span></div></div>';

  elements.reportList.innerHTML = reports.length
    ? reports
        .map(
          (report) => `
        <div class="report">
          <div class="report-title"><strong>${escapeHtml(report.type)}</strong><span>${escapeHtml(report.path)}</span></div>
          <button type="button" data-export="${escapeHtml(report.type)}">EXPORT</button>
        </div>
      `,
        )
        .join("")
    : '<div class="report"><div class="report-title"><strong>Current report</strong><span>dashboard/data/latest-report.json</span></div><button type="button" data-export="json">EXPORT</button></div>';

  document.querySelectorAll("[data-export]").forEach((button) => {
    button.addEventListener("click", () => exportJson(button.dataset.export || "json"));
  });

  elements.branchList.innerHTML = branches.length
    ? branches
        .map(
          (branch) => `
        <div class="branch">
          <div class="branch-title"><strong>${escapeHtml(branch.name)}</strong><span>${escapeHtml(branch.note)}</span></div>
          <span class="provider-state ok">${escapeHtml(branch.commit)}</span>
        </div>
      `,
        )
        .join("")
    : '<div class="branch"><div class="branch-title"><strong>No branch status loaded</strong><span>Load project-status.json.</span></div></div>';

  elements.qualityList.innerHTML = quality.length
    ? quality
        .map(
          (gate) =>
            `<div><span>${escapeHtml(gate.name)}</span><strong class="${gate.status === "pass" ? "ok" : "bad"}">${escapeHtml(gate.result)}</strong></div>`,
        )
        .join("")
    : '<div><span>Quality gates</span><strong>not loaded</strong></div>';

  elements.osvList.innerHTML = `
    <div><dt>Status</dt><dd class="${safeClass(osv.status_class, "")}">${escapeHtml(osv.status || "not loaded")}</dd></div>
    <div><dt>Source</dt><dd>${escapeHtml(osv.source || "-")}</dd></div>
    <div><dt>Cache path</dt><dd>${escapeHtml(osv.cache_path || "-")}</dd></div>
    <div><dt>Last query</dt><dd>${escapeHtml(osv.last_query || "-")}</dd></div>
    <div><dt>Advisories</dt><dd>${osv.advisories ?? "-"}</dd></div>
  `;

  elements.providerFallback.textContent = providers.length
    ? providers.map((provider) => `${provider.name}: ${provider.detail}`).join("\n")
    : "No provider status artifact loaded.";
}

function renderDebug() {
  const trace = state.report?.rule_trace || [];
  elements.ruleTrace.textContent = trace.length ? trace.join("\n") : "No rule trace entries in loaded report.";
  elements.scanPlan.textContent = JSON.stringify(state.report?.scan_plan || {}, null, 2);
}

function render() {
  const items = filteredFindings();
  renderFilters();
  renderSummary(items);
  renderRows(items);
  renderDetail(items);
  renderBars();
  renderTrend();
  renderStatus();
  renderDebug();
}

function exportJson(type) {
  const payload = {
    project: "PyPi-AI",
    artifact_type: type,
    source: "loaded PyPi-AI report",
    report: state.report,
    status: state.status,
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `pypi-ai-dashboard-${type.toLowerCase()}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
}

async function readFile(file) {
  return JSON.parse(await file.text());
}

elements.searchBox.addEventListener("input", (event) => {
  state.search = event.target.value;
  render();
});

elements.categoryFilter.addEventListener("change", (event) => {
  state.category = event.target.value;
  render();
});

elements.packageFilter.addEventListener("change", (event) => {
  state.packageName = event.target.value;
  render();
});

elements.reportFile.addEventListener("change", async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;
  state.report = await readFile(file);
  state.selectedId = normalizeFindings(state.report)[0]?.id || "";
  state.search = "";
  state.severity = "all";
  state.category = "all";
  state.packageName = "all";
  elements.searchBox.value = "";
  render();
});

elements.statusFile.addEventListener("change", async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;
  state.status = await readFile(file);
  render();
});

document.querySelectorAll(".segment").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".segment").forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
    elements.debugGrid.classList.toggle("hidden", button.dataset.mode !== "debug");
  });
});

async function bootstrap() {
  try {
    state.report = await loadJson("./data/latest-report.json");
    state.selectedId = normalizeFindings(state.report)[0]?.id || "";
  } catch {
    state.report = null;
  }
  try {
    state.status = await loadJson("./data/project-status.json");
  } catch {
    state.status = null;
  }
  render();
}

bootstrap();
