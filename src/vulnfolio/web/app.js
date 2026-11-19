"use strict";

// M0 deliberately has no runtime framework or custom widget library.
// Presentation is handled by pinned Tabler / Bootstrap components.
const $ = (id) => document.getElementById(id);
const state = {page: 1, perPage: 25, query: "", count: 0, request: 0};

function showAlert(message) {
  const element = $("alert");
  element.textContent = message;
  element.classList.toggle("d-none", !message);
}

function formatDate(value) {
  if (!value) return "Unknown";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "Unknown" : parsed.toISOString().replace("T", " ").slice(0, 19);
}

async function requestJSON(path) {
  const response = await fetch(path, {headers: {"Accept": "application/json"}, cache: "no-store"});
  if (!response.ok) throw new Error("HTTP " + response.status);
  return response.json();
}

function newCell(value, className) {
  const td = document.createElement("td");
  if (className) td.className = className;
  td.textContent = value == null ? "—" : String(value);
  return td;
}

function newBadge(value) {
  const badge = document.createElement("span");
  const score = Number(value);
  let variant = "secondary";
  if (value !== null && Number.isFinite(score)) {
    variant = score >= 9 ? "red" : score >= 7 ? "orange" : score >= 4 ? "yellow" : "green";
  }
  badge.className = "badge bg-" + variant + "-lt";
  badge.textContent = value == null ? "Unknown" : score.toFixed(1);
  return badge;
}

function renderRows(items) {
  const tbody = $("vulnerability-rows");
  tbody.replaceChildren();
  if (!items.length) {
    const tr = document.createElement("tr");
    const td = newCell(state.query ? "No matching records." : "No data yet. Use the manual sync CLI to import a known CVE.", "text-secondary");
    td.colSpan = 5;
    tr.append(td);
    tbody.append(tr);
    return;
  }
  for (const item of items) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    const link = document.createElement("a");
    link.href = "#detail";
    link.textContent = item.id;
    link.addEventListener("click", (event) => {event.preventDefault(); showDetail(item.id);});
    td.append(link);
    tr.append(td);
    tr.append(newCell(item.title));
    const severity = document.createElement("td");
    severity.append(newBadge(item.cvss_score));
    tr.append(severity);
    tr.append(newCell(item.provider, "text-secondary"));
    tr.append(newCell(formatDate(item.updated_at), "text-secondary"));
    tbody.append(tr);
  }
}

function pagination() {
  const start = state.count ? ((state.page - 1) * state.perPage + 1) : 0;
  const end = Math.min(state.page * state.perPage, state.count);
  $("pagination-count").textContent = start + "–" + end + " of " + state.count;
  $("prev").disabled = state.page <= 1;
  $("next").disabled = state.page * state.perPage >= state.count;
}

async function loadList() {
  const requestId = ++state.request;
  const params = new URLSearchParams({q: state.query, page: String(state.page), per_page: String(state.perPage)});
  try {
    const result = await requestJSON("/api/v1/vulnerabilities?" + params.toString());
    if (requestId !== state.request) return;
    state.count = result.metadata.count;
    renderRows(result.data);
    pagination();
    showAlert("");
  } catch (error) {
    if (requestId !== state.request) return;
    state.count = 0;
    renderRows([]);
    pagination();
    showAlert("Unable to load the local API: " + error.message);
  }
}

async function loadHealth() {
  try {
    const health = await requestJSON("/api/v1/health");
    $("count").textContent = health.vulnerability_count;
    $("last-success").textContent = formatDate(health.upstream.last_success_at);
    const badge = $("source-status");
    const state = health.status;
    badge.className = "badge bg-" + (state === "ready" ? "green" : state === "degraded" ? "red" : "secondary") + "-lt";
    badge.textContent = state === "ready" ? "Last sync succeeded" : state === "degraded" ? "Last sync failed" : "Not synced";
    if (health.upstream.last_error) showAlert("Upstream sync issue: " + health.upstream.last_error + " (previous data is preserved)");
  } catch (error) {
    $("source-status").textContent = "Local API unavailable";
    showAlert("Unable to load health status: " + error.message);
  }
}

async function showDetail(id) {
  $("detail").classList.remove("d-none");
  $("detail-title").textContent = id;
  $("detail-description").textContent = "Loading…";
  $("detail-references").replaceChildren();
  try {
    const item = await requestJSON("/api/v1/vulnerabilities/" + encodeURIComponent(id));
    $("detail-title").textContent = item.id + " — " + item.title;
    $("detail-description").textContent = item.description || "No description available";
    $("detail-published").textContent = formatDate(item.published_at);
    $("detail-updated").textContent = formatDate(item.updated_at);
    $("detail-fetched").textContent = formatDate(item.fetched_at);
    const refs = $("detail-references");
    for (const url of item.references || []) {
      if (!/^https?:\/\//i.test(url)) continue;
      const li = document.createElement("li");
      const a = document.createElement("a");
      a.href = url;
      a.textContent = url;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      li.append(a);
      refs.append(li);
    }
    if (!refs.childElementCount) refs.append(document.createTextNode("No references"));
  } catch (error) {
    $("detail-description").textContent = "Unable to load details: " + error.message;
  }
  $("detail").scrollIntoView({behavior: "smooth", block: "start"});
}

$("search-form").addEventListener("submit", (event) => {
  event.preventDefault();
  state.query = $("q").value.trim();
  state.page = 1;
  loadList();
});
$("reload").addEventListener("click", () => {loadList(); loadHealth();});
$("prev").addEventListener("click", () => {state.page = Math.max(1, state.page - 1); loadList();});
$("next").addEventListener("click", () => {if (state.page * state.perPage < state.count) {state.page++; loadList();}});
$("close-detail").addEventListener("click", () => $("detail").classList.add("d-none"));
loadHealth();
loadList();
