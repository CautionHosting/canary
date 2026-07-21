(() => {
  "use strict";

  const dialog = document.querySelector("#target-inspector");
  if (!(dialog instanceof HTMLDialogElement)) return;

  const panels = new Map(
    [...dialog.querySelectorAll("[data-panel]")].map((panel) => [panel.dataset.panel, panel]),
  );
  const tabs = [...dialog.querySelectorAll("[data-tab]")];
  let currentTarget = null;
  let loadGeneration = 0;

  const byId = (id) => document.getElementById(id);

  function targetPath(kind) {
    return `/targets/${encodeURIComponent(currentTarget.id)}/${kind}`;
  }

  function verificationCommand(targetId) {
    const target = targetId ? ` \\\n  --target ${targetId}` : "";
    const origin = window.location.protocol === "https:"
      ? window.location.origin
      : "https://<deployed-canary-origin>";
    return `canaryctl verify \\\n  --url ${origin} \\\n  --pcrs-file .caution/trusted_hashes.json${target}`;
  }

  function setCommand(element, targetId) {
    if (element) element.textContent = verificationCommand(targetId);
  }

  function setActiveTab(name) {
    for (const tab of tabs) {
      const active = tab.dataset.tab === name;
      tab.setAttribute("aria-selected", String(active));
      tab.tabIndex = active ? 0 : -1;
    }
    for (const [panelName, panel] of panels) {
      panel.hidden = panelName !== name;
    }
    if (name !== "target") loadArtifact(name);
  }

  function setArtifactState(name, message, state = "loading") {
    const panel = panels.get(name);
    const output = panel?.querySelector("[data-artifact-output]");
    if (!output) return;
    output.dataset.state = state;
    output.textContent = message;
  }

  async function requestJson(path) {
    const response = await fetch(path, {
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    const text = await response.text();
    let value;
    try {
      value = JSON.parse(text);
    } catch {
      throw new Error(`The endpoint returned non-JSON data (${response.status}).`);
    }
    if (!response.ok) {
      const reason = value?.error === "no_evidence"
        ? "No evidence is attached to the current state. Pending, stale, unreachable, and some failed states legitimately have none."
        : `The endpoint returned ${response.status}: ${value?.error || "request_failed"}.`;
      throw new Error(reason);
    }
    return value;
  }

  function renderJson(name, value) {
    const output = panels.get(name)?.querySelector("[data-artifact-output]");
    if (!output) return;
    output.dataset.state = "ready";
    output.textContent = JSON.stringify(value, null, 2);
  }

  function appendCell(row, value, className) {
    const cell = document.createElement("td");
    if (className) cell.className = className;
    cell.textContent = value ?? "—";
    row.append(cell);
  }

  function renderHistory(value) {
    const panel = panels.get("history");
    const output = panel?.querySelector("[data-artifact-output]");
    if (!output) return;
    output.dataset.state = "ready";
    output.replaceChildren();

    const observations = Array.isArray(value?.observations) ? value.observations : [];
    if (observations.length === 0) {
      output.textContent = "No completed probe attempts are recorded for this process lifetime.";
      return;
    }

    const table = document.createElement("table");
    const head = document.createElement("thead");
    const headerRow = document.createElement("tr");
    for (const label of ["Attempted", "State", "Probe result", "Latency", "Evidence digest"]) {
      const th = document.createElement("th");
      th.scope = "col";
      th.textContent = label;
      headerRow.append(th);
    }
    head.append(headerRow);
    table.append(head);

    const body = document.createElement("tbody");
    for (const observation of observations) {
      const row = document.createElement("tr");
      appendCell(row, observation.attempted_at);
      appendCell(row, observation.status, `history-status history-status-${String(observation.status || "").toLowerCase()}`);
      appendCell(row, observation.attempt_reason);
      appendCell(row, observation.latency_ms == null ? "—" : `${observation.latency_ms} ms`);
      appendCell(row, observation.evidence_digest, "digest-cell");
      body.append(row);
    }
    table.append(body);
    output.append(table);
  }

  async function loadArtifact(name) {
    const panel = panels.get(name);
    if (!panel || panel.dataset.loaded === "true" || !currentTarget) return;

    const generation = loadGeneration;
    setArtifactState(name, `Loading ${name}…`);
    try {
      const value = await requestJson(targetPath(name));
      if (generation !== loadGeneration) return;
      if (name === "history") renderHistory(value);
      else renderJson(name, value);
      panel.dataset.loaded = "true";
    } catch (error) {
      if (generation !== loadGeneration) return;
      setArtifactState(name, error instanceof Error ? error.message : "Unable to load this artifact.", "error");
    }
  }

  function setLink(id, kind) {
    const link = byId(id);
    if (link) link.href = targetPath(kind);
  }

  function openTarget(card) {
    loadGeneration += 1;
    currentTarget = {
      id: card.dataset.targetId,
      name: card.dataset.targetName,
      origin: card.dataset.targetOrigin,
      status: card.dataset.targetStatus,
      reason: card.dataset.targetReason,
      observed: card.dataset.targetObserved || "—",
      expires: card.dataset.targetExpires,
      warning: card.dataset.targetWarning || "None",
    };

    byId("inspector-kicker").textContent = currentTarget.id;
    byId("inspector-title").textContent = currentTarget.name;
    byId("inspector-status").textContent = currentTarget.status;
    byId("inspector-status").className = `status-badge status-${currentTarget.status.toLowerCase()}`;
    byId("inspector-origin").textContent = currentTarget.origin;
    byId("inspector-reason").textContent = currentTarget.reason;
    byId("inspector-observed").textContent = currentTarget.observed;
    byId("inspector-expires").textContent = currentTarget.expires;
    byId("inspector-warning").textContent = currentTarget.warning;
    setCommand(byId("target-command"), currentTarget.id);
    setLink("statement-json-link", "statement");
    setLink("evidence-json-link", "evidence");
    setLink("history-json-link", "history");

    for (const [name, panel] of panels) {
      panel.dataset.loaded = name === "target" ? "true" : "false";
      if (name !== "target") setArtifactState(name, "Select this view to load its current JSON.", "idle");
    }
    setActiveTab("target");
    dialog.showModal();
    history.replaceState(null, "", `#target-${encodeURIComponent(currentTarget.id)}`);
  }

  async function copyText(button) {
    const selector = button.dataset.copy;
    const source = selector ? document.querySelector(selector) : null;
    if (!source) return;
    const text = source.textContent;
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const textarea = document.createElement("textarea");
      textarea.value = text;
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.append(textarea);
      textarea.select();
      document.execCommand("copy");
      textarea.remove();
    }
    const original = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => { button.textContent = original; }, 1400);
  }

  document.addEventListener("click", (event) => {
    const openButton = event.target.closest("[data-open-target]");
    if (openButton) {
      const card = openButton.closest("[data-target-id]");
      if (card) openTarget(card);
      return;
    }

    const tab = event.target.closest("[data-tab]");
    if (tab) {
      setActiveTab(tab.dataset.tab);
      return;
    }

    const copyButton = event.target.closest("[data-copy]");
    if (copyButton) copyText(copyButton);
  });

  dialog.querySelector("[data-close]")?.addEventListener("click", () => dialog.close());
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close();
  });
  dialog.addEventListener("close", () => {
    currentTarget = null;
    loadGeneration += 1;
    history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
  });

  for (const tab of tabs) {
    tab.addEventListener("keydown", (event) => {
      if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
      event.preventDefault();
      const offset = event.key === "ArrowRight" ? 1 : -1;
      const index = tabs.indexOf(tab);
      const next = tabs[(index + offset + tabs.length) % tabs.length];
      next.focus();
      setActiveTab(next.dataset.tab);
    });
  }

  setCommand(document.querySelector("#all-targets-command"), null);
  if (window.location.protocol !== "https:") {
    const note = document.querySelector("#command-trust-note");
    if (note) note.textContent = "This HTTP page is a local UI preview only. Verify the deployed HTTPS origin with independently reproduced Canary PCRs.";
  }

  let hashTarget = "";
  try {
    hashTarget = decodeURIComponent(window.location.hash.replace(/^#target-/, ""));
  } catch {
    hashTarget = "";
  }
  if (hashTarget && window.location.hash.startsWith("#target-")) {
    const card = [...document.querySelectorAll("[data-target-id]")]
      .find((candidate) => candidate.dataset.targetId === hashTarget);
    if (card) openTarget(card);
  }
})();
