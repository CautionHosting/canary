(() => {
  "use strict";

  const dialog = document.querySelector("#target-inspector");
  if (!(dialog instanceof HTMLDialogElement)) return;

  const panels = new Map(
    [...dialog.querySelectorAll("[data-panel]")].map((panel) => [panel.dataset.panel, panel]),
  );
  const tabs = [...dialog.querySelectorAll("[data-tab]")];
  const isNitroEnclave = document.body.dataset.runtimeEnvironment === "nitro_enclave";
  const byId = (id) => document.getElementById(id);
  let currentDeployment = null;
  let loadGeneration = 0;

  function deploymentPath(kind) {
    return `/targets/${encodeURIComponent(currentDeployment.id)}/${kind}`;
  }

  function enrollmentCommand() {
    if (!isNitroEnclave) return `canaryctl enroll --url ${window.location.origin} --insecure`;
    return `caution verify --save-pcrs\n\ncanaryctl enroll --url ${window.location.origin} --pcrs .caution/trusted_hashes.json`;
  }

  function verificationCommand(deploymentId, attemptId) {
    const deployment = deploymentId ? ` \\\n  --deployment ${deploymentId}` : "";
    const attempt = attemptId ? ` \\\n  --attempt ${attemptId}` : "";
    const trust = isNitroEnclave
      ? "--pcrs .caution/trusted_hashes.json"
      : "--insecure";
    return `canaryctl verify \\\n  --url ${window.location.origin} \\\n  ${trust}${deployment}${attempt}`;
  }

  function setCommand(element, deploymentId) {
    if (element) element.textContent = verificationCommand(deploymentId);
  }

  function setActiveTab(name) {
    for (const tab of tabs) {
      const active = tab.dataset.tab === name;
      tab.setAttribute("aria-selected", String(active));
      tab.tabIndex = active ? 0 : -1;
    }
    for (const [panelName, panel] of panels) panel.hidden = panelName !== name;
    if (name === "history") loadHistory();
  }

  function setHistoryState(message, state = "loading") {
    const output = panels.get("history")?.querySelector("[data-artifact-output]");
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
    if (!response.ok) throw new Error(`The endpoint returned ${response.status}: ${value?.error || "request_failed"}.`);
    return value;
  }

  function appendCell(row, value, className) {
    const cell = document.createElement("td");
    if (className) cell.className = className;
    cell.textContent = value ?? "—";
    row.append(cell);
  }

  function renderHistory(value) {
    const output = panels.get("history")?.querySelector("[data-artifact-output]");
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
    for (const label of ["Attempted", "State", "Result", "Latency", "Verify"]) {
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
      const actions = document.createElement("td");
      actions.className = "history-actions";
      const copy = document.createElement("button");
      copy.className = "copy-button";
      copy.type = "button";
      copy.dataset.copyText = verificationCommand(currentDeployment.id, observation.id);
      copy.textContent = "Copy CLI";
      actions.append(copy);
      row.append(actions);
      body.append(row);
    }
    table.append(body);
    output.append(table);
  }

  async function loadHistory() {
    const panel = panels.get("history");
    if (!panel || panel.dataset.loaded === "true" || !currentDeployment) return;
    const generation = loadGeneration;
    setHistoryState("Loading history…");
    try {
      const value = await requestJson(deploymentPath("history"));
      if (generation !== loadGeneration) return;
      renderHistory(value);
      panel.dataset.loaded = "true";
    } catch (error) {
      if (generation !== loadGeneration) return;
      setHistoryState(error instanceof Error ? error.message : "Unable to load history.", "error");
    }
  }

  function setLink(id, kind) {
    const link = byId(id);
    if (link) link.href = deploymentPath(kind);
  }

  function openDeployment(card) {
    loadGeneration += 1;
    currentDeployment = {
      id: card.dataset.targetId,
      name: card.dataset.targetName,
      origin: card.dataset.targetOrigin,
      status: card.dataset.targetStatus,
      reason: card.dataset.targetReason,
      observed: card.dataset.targetObserved || "—",
      expires: card.dataset.targetExpires,
      warning: card.dataset.targetWarning || "None",
    };

    byId("inspector-kicker").textContent = currentDeployment.id;
    byId("inspector-title").textContent = currentDeployment.name;
    byId("inspector-status").textContent = currentDeployment.status;
    byId("inspector-status").className = `status-badge status-${currentDeployment.status.toLowerCase()}`;
    byId("inspector-origin").textContent = currentDeployment.origin;
    byId("inspector-reason").textContent = currentDeployment.reason;
    byId("inspector-observed").textContent = currentDeployment.observed;
    byId("inspector-expires").textContent = currentDeployment.expires;
    byId("inspector-warning").textContent = currentDeployment.warning;
    setCommand(byId("deployment-command"), currentDeployment.id);
    setLink("statement-json-link", "statement");
    setLink("evidence-json-link", "evidence");
    setLink("history-json-link", "history");

    for (const [name, panel] of panels) {
      panel.dataset.loaded = name === "overview" ? "true" : "false";
      if (name === "history") setHistoryState("Select this view to load recorded attempts.", "idle");
    }
    setActiveTab("overview");
    dialog.showModal();
    history.replaceState(null, "", `#deployment-${encodeURIComponent(currentDeployment.id)}`);
  }

  async function copyText(button) {
    const selector = button.dataset.copy;
    const source = selector ? document.querySelector(selector) : null;
    const text = button.dataset.copyText || source?.textContent;
    if (!text) return;
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
      if (card) openDeployment(card);
      return;
    }
    const tab = event.target.closest("[data-tab]");
    if (tab) {
      setActiveTab(tab.dataset.tab);
      return;
    }
    const copyButton = event.target.closest("[data-copy], [data-copy-text]");
    if (copyButton) copyText(copyButton);
  });

  dialog.querySelector("[data-close]")?.addEventListener("click", () => dialog.close());
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close();
  });
  dialog.addEventListener("close", () => {
    currentDeployment = null;
    loadGeneration += 1;
    history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
  });

  for (const tab of tabs) {
    tab.addEventListener("keydown", (event) => {
      if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
      event.preventDefault();
      const offset = event.key === "ArrowRight" ? 1 : -1;
      const next = tabs[(tabs.indexOf(tab) + offset + tabs.length) % tabs.length];
      next.focus();
      setActiveTab(next.dataset.tab);
    });
  }

  const enrollment = document.querySelector("#enroll-command");
  if (enrollment) enrollment.textContent = enrollmentCommand();
  setCommand(document.querySelector("#all-deployments-command"), null);

  let hashDeployment = "";
  try {
    hashDeployment = decodeURIComponent(window.location.hash.replace(/^#deployment-/, ""));
  } catch {
    hashDeployment = "";
  }
  if (hashDeployment && window.location.hash.startsWith("#deployment-")) {
    const card = [...document.querySelectorAll("[data-target-id]")]
      .find((candidate) => candidate.dataset.targetId === hashDeployment);
    if (card) openDeployment(card);
  }
})();
