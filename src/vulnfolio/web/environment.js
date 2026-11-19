"use strict";

const byId = (id) => document.getElementById(id);
const state = {profile: "", asset: ""};
const STATUSES = [
  ["new", "New / review required"],
  ["investigating", "Investigating"],
  ["affected", "Affected (manual assessment)"],
  ["in_progress", "In progress"],
  ["mitigated", "Mitigated"],
  ["not_affected", "Not affected"],
  ["accepted_risk", "Accepted risk"],
];

function message(id, text) {
  byId(id).textContent = text;
  byId(id).classList.toggle("d-none", !text);
}

function cell(text) {
  const td = document.createElement("td");
  td.textContent = text == null ? "—" : String(text);
  return td;
}

function option(value, title) {
  const el = document.createElement("option");
  el.value = value;
  el.textContent = title;
  return el;
}

function resetRows(id, columns, text) {
  const body = byId(id);
  body.replaceChildren();
  const tr = document.createElement("tr");
  const td = cell(text);
  td.colSpan = columns;
  td.className = "text-secondary";
  tr.append(td);
  body.append(tr);
}

async function api(path, method = "GET", body) {
  const config = {
    method,
    cache: "no-store",
    headers: {"Accept": "application/json"},
  };
  if (body !== undefined) {
    config.headers["Content-Type"] = "application/json";
    config.body = JSON.stringify(body);
  }
  const response = await fetch(path, config);
  if (!response.ok) {
    let detail = "HTTP " + response.status;
    try {
      const error = await response.json();
      if (typeof error.detail === "string") detail = error.detail;
    } catch (_) { /* not JSON */ }
    throw new Error(detail);
  }
  return response.status === 204 ? null : response.json();
}

async function runAction(task, success) {
  message("environment-alert", "");
  message("environment-notice", "");
  try {
    await task();
    message("environment-notice", success);
  } catch (error) {
    message("environment-alert", error.message);
  }
}

async function loadProfiles(preferred = state.profile) {
  const result = await api("/api/v1/profiles");
  const select = byId("profile-select");
  select.replaceChildren(option("", "Select a profile"));
  for (const profile of result.data) {
    select.append(option(profile.id, profile.name + " (" + profile.asset_count + " assets)"));
  }
  state.profile = result.data.some((item) => item.id === preferred)
    ? preferred : (result.data[0]?.id || "");
  select.value = state.profile;
  await loadAssets();
}

async function loadAssets(preferred = state.asset) {
  const select = byId("asset-select");
  select.replaceChildren(option("", "Select an asset"));
  state.asset = "";
  if (!state.profile) {
    resetRows("product-rows", 4, "Create a profile and asset first.");
    resetRows("candidate-rows", 4, "Create a profile first.");
    byId("coverage").textContent = "No profile selected.";
    byId("import-history").textContent = "";
    return;
  }
  const result = await api("/api/v1/profiles/" + encodeURIComponent(state.profile) + "/assets");
  for (const asset of result.data) {
    select.append(option(asset.id, asset.name + (asset.os_family ? " · " + asset.os_family : "")));
  }
  state.asset = result.data.some((item) => item.id === preferred)
    ? preferred : (result.data[0]?.id || "");
  select.value = state.asset;
  await Promise.all([loadProducts(), loadCandidates(), loadImportHistory()]);
}

async function loadProducts() {
  if (!state.asset) {
    resetRows("product-rows", 4, "Create an asset first.");
    return;
  }
  const result = await api("/api/v1/assets/" + encodeURIComponent(state.asset) + "/products");
  const rows = byId("product-rows");
  rows.replaceChildren();
  if (!result.data.length) return resetRows("product-rows", 4, "No installed software yet.");
  for (const product of result.data) {
    const tr = document.createElement("tr");
    tr.append(cell(product.vendor || "—"), cell(product.name), cell(product.version || "Unknown"));
    const td = document.createElement("td");
    if (product.origin === "imported") {
      td.append(document.createTextNode("Imported (" + (product.manager || "unknown manager") + ")"));
    } else {
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "btn btn-sm btn-outline-danger";
      remove.textContent = "Remove";
      remove.addEventListener("click", () => runAction(async () => {
        await api("/api/v1/products/" + encodeURIComponent(product.id), "DELETE");
        await Promise.all([loadProducts(), loadCandidates()]);
      }, "Software entry removed."));
      td.append(remove);
    }
    tr.append(td);
    rows.append(tr);
  }
}

async function loadImportHistory() {
  if (!state.profile) {
    byId("import-history").textContent = "";
    return;
  }
  const result = await api("/api/v1/profiles/" + encodeURIComponent(state.profile) + "/imports");
  if (!result.data.length) {
    byId("import-history").textContent = "No previous imports for this profile.";
    return;
  }
  const latest = result.data[0];
  byId("import-history").textContent =
    "Latest import: " + latest.collector + " · " + latest.asset_count +
    " assets · " + latest.error_count + " collection errors · " + latest.imported_at;
}

async function loadCandidates() {
  if (!state.profile) return;
  const params = new URLSearchParams({include_closed: String(byId("include-closed").checked)});
  const result = await api("/api/v1/profiles/" + encodeURIComponent(state.profile) +
                           "/candidates?" + params.toString());
  const coverage = result.metadata;
  byId("coverage").textContent =
    "Compared " + coverage.checked_local_cves + " locally stored CVE records · " +
    coverage.count + " potential matches" +
    (coverage.complete ? "." : " · INCOMPLETE COVERAGE: scan limited to first 2000 CVEs.");
  const rows = byId("candidate-rows");
  rows.replaceChildren();
  if (!result.data.length) return resetRows("candidate-rows", 4,
    "No potential matches in this local dataset. This does not establish that assets are safe.");
  for (const candidate of result.data) {
    const tr = document.createElement("tr");
    const details = cell(candidate.asset_name + " · " + candidate.product_name +
                         (candidate.installed_version ? " " + candidate.installed_version : ""));
    const cve = document.createElement("td");
    const link = document.createElement("a");
    link.href = "/?cve=" + encodeURIComponent(candidate.cve_id);
    link.textContent = candidate.cve_id;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.title = candidate.cve_title;
    cve.append(link);
    const basis = cell(candidate.match_basis === "exact_version_listed_affected"
      ? "Exact version listed" : "Product name only");
    basis.title = candidate.evidence;
    if (!candidate.vendor_verified) basis.append(document.createTextNode(" · vendor unverified"));

    const controls = document.createElement("td");
    const group = document.createElement("div");
    group.className = "d-flex gap-2 flex-wrap";
    const select = document.createElement("select");
    select.className = "form-select form-select-sm";
    select.setAttribute("aria-label", "Assessment for " + candidate.cve_id + " on " + candidate.asset_name);
    for (const [value, label] of STATUSES) select.append(option(value, label));
    select.value = candidate.assessment.status;
    const note = document.createElement("input");
    note.className = "form-control form-control-sm";
    note.type = "text";
    note.maxLength = 1000;
    note.placeholder = "Assessment note";
    note.value = candidate.assessment.note || "";
    note.setAttribute("aria-label", "Note for " + candidate.cve_id + " on " + candidate.asset_name);
    const save = document.createElement("button");
    save.type = "button";
    save.className = "btn btn-sm btn-primary";
    save.textContent = "Save";
    save.addEventListener("click", () => runAction(async () => {
      await api("/api/v1/assets/" + encodeURIComponent(candidate.asset_id) + "/assessments/" +
                encodeURIComponent(candidate.cve_id), "PUT",
                {status: select.value, note: note.value});
      await loadCandidates();
    }, "Assessment saved for " + candidate.cve_id + " / " + candidate.asset_name + "."));
    group.append(select, note, save);
    controls.append(group);
    tr.append(details, cve, basis, controls);
    rows.append(tr);
  }
}

byId("import-form").addEventListener("submit", (event) => {
  event.preventDefault();
  runAction(async () => {
    if (!state.profile) throw new Error("Create or select a profile first.");
    const file = byId("import-file").files?.[0];
    if (!file) throw new Error("Select a JSON file.");
    if (file.size > 2 * 1024 * 1024) throw new Error("JSON exceeds 2 MiB.");
    let payload;
    try {
      payload = JSON.parse(await file.text());
    } catch (_) {
      throw new Error("The selected file is not valid JSON.");
    }
    if (payload?.profile_id !== state.profile) {
      throw new Error("The JSON profile_id does not match the selected profile. Generate it with --profile " + state.profile);
    }
    const result = await api("/api/v1/profiles/" + encodeURIComponent(state.profile) +
                             "/imports", "POST", payload);
    byId("import-summary").textContent =
      (result.duplicate ? "Already imported (no changes): " : "Imported: ") +
      result.assets_seen + " assets · " + result.error_count + " collection errors · " +
      result.collector;
    byId("import-form").reset();
    await loadAssets(state.asset);
  }, "Inventory processing complete.");
});

byId("profile-form").addEventListener("submit", (event) => {
  event.preventDefault();
  runAction(async () => {
    const created = await api("/api/v1/profiles", "POST", {name: byId("profile-name").value});
    byId("profile-form").reset();
    await loadProfiles(created.id);
  }, "Profile created.");
});
byId("asset-form").addEventListener("submit", (event) => {
  event.preventDefault();
  runAction(async () => {
    if (!state.profile) throw new Error("Create a profile first.");
    const created = await api("/api/v1/profiles/" + encodeURIComponent(state.profile) + "/assets", "POST", {
      name: byId("asset-name").value,
      os_family: byId("asset-os").value,
      os_version: byId("asset-version").value
    });
    byId("asset-form").reset();
    await loadAssets(created.id);
  }, "Asset created.");
});
byId("product-form").addEventListener("submit", (event) => {
  event.preventDefault();
  runAction(async () => {
    if (!state.asset) throw new Error("Create an asset first.");
    await api("/api/v1/assets/" + encodeURIComponent(state.asset) + "/products", "POST", {
      name: byId("product-name").value,
      vendor: byId("product-vendor").value,
      version: byId("product-version").value
    });
    byId("product-form").reset();
    await Promise.all([loadProducts(), loadCandidates()]);
  }, "Software registered.");
});
byId("profile-select").addEventListener("change", () => {
  state.profile = byId("profile-select").value;
  state.asset = "";
  runAction(() => loadAssets(), "");
});
byId("asset-select").addEventListener("change", () => {
  state.asset = byId("asset-select").value;
  runAction(() => loadProducts(), "");
});
byId("include-closed").addEventListener("change", () => {
  runAction(() => loadCandidates(), "");
});
byId("refresh-candidates").addEventListener("click", () => {
  runAction(() => loadCandidates(), "");
});
runAction(() => loadProfiles(), "");
