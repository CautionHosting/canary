//! Server-rendered public status page with a small same-origin artifact explorer.
//!
//! Configuration-derived strings are HTML-escaped. The static client script
//! fetches read-only artifacts and performs an explicit, nonce-bound
//! browser-side verification of Canary's own Nitro attestation when available.

use canary_core::{node::IdentityMode, statement::CADDY_CLAIM_TYPE};

use crate::model::{ExecutionEnvironment, RuntimeSnapshot};

pub const UI_SCRIPT: &str = include_str!("ui.js");

const PAGE_HEAD: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>Canary status</title>
<style>
:root {
  --bg: #080c10;
  --surface: #0e151b;
  --surface-raised: #121b22;
  --surface-soft: #0a1116;
  --border: #22313a;
  --border-strong: #36505d;
  --text: #d9e4e9;
  --muted: #83949e;
  --accent: #63dcff;
  --accent-bright: #b8f2ff;
  --accent-soft: rgba(99, 220, 255, .09);
  --danger: #ff8193;
  --warning: #e8c872;
  --success: #5cff9d;
}

* { box-sizing: border-box; }
html { background: var(--bg); scroll-behavior: smooth; }
body {
  min-width: 300px;
  min-height: 100vh;
  margin: 0;
  color: var(--text);
  background:
    radial-gradient(circle at 82% -10%, rgba(99, 220, 255, .07), transparent 30%),
    linear-gradient(180deg, rgba(99, 220, 255, .025), transparent 360px),
    var(--bg);
  font: 14px/1.58 ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
  -webkit-font-smoothing: antialiased;
}

button, input { font: inherit; }
a { color: var(--accent); text-underline-offset: 3px; }
a:hover { color: var(--accent-bright); }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; }
[hidden] { display: none !important; }

.shell { width: min(1180px, 100%); margin: 0 auto; padding: 64px 28px 84px; }
.eyebrow, .label, dt, .panel-kicker {
  color: var(--muted);
  font-size: 11px;
  font-weight: 700;
  letter-spacing: .12em;
  text-transform: uppercase;
}
.eyebrow { margin: 0 0 12px; color: var(--accent); letter-spacing: .06em; text-transform: none; overflow-wrap: anywhere; }
h1 { margin: 0; color: #f2f8fa; font-size: clamp(34px, 5vw, 54px); font-weight: 500; letter-spacing: -.05em; line-height: 1.02; }
.lede { max-width: 760px; margin: 18px 0 0; color: #aab8bf; font-size: 15px; }

.intro { margin-bottom: 42px; }
.topline { display: flex; align-items: flex-start; justify-content: space-between; gap: 28px; }
.raw-nav { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 6px; }
.raw-nav a, .raw-link {
  padding: 7px 9px;
  color: var(--accent);
  text-decoration: none;
  border: 1px solid var(--border);
  background: rgba(8, 12, 16, .55);
  font-size: 11px;
}
.raw-nav a:hover, .raw-link:hover { background: var(--accent-soft); border-color: rgba(99, 220, 255, .32); }

.label, dt { display: block; margin: 0 0 5px; }
.value, dd { min-width: 0; margin: 0; overflow-wrap: anywhere; color: #cbd7dc; }

.self-check {
  --self-check-color: var(--warning);
  margin: 0 0 42px;
  overflow: hidden;
  background: linear-gradient(135deg, color-mix(in srgb, var(--self-check-color) 5%, var(--surface)) 0%, var(--surface) 55%);
  border: 1px solid var(--border);
  border-top: 2px solid var(--self-check-color);
}
.self-check--enclave { --self-check-color: var(--success); }
.self-check-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 24px; padding: 20px 22px 18px; background: rgba(18, 27, 34, .68); border-bottom: 1px solid var(--border); }
.self-check-kicker { display: block; margin-bottom: 4px; color: var(--accent); font-size: 10px; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; }
.self-check h2 { margin: 0; color: #edf5f8; font-size: 18px; font-weight: 550; }
.self-check-badge { flex: 0 0 auto; display: inline-flex; align-items: center; gap: 7px; padding: 6px 9px; color: var(--self-check-color); background: color-mix(in srgb, var(--self-check-color) 10%, transparent); border: 1px solid color-mix(in srgb, var(--self-check-color) 38%, transparent); font-size: 10px; font-weight: 700; letter-spacing: .08em; }
.self-check-badge::before { content: ""; width: 7px; height: 7px; background: currentColor; border-radius: 50%; box-shadow: 0 0 9px currentColor; }
.self-check-summary { margin: 0; padding: 18px 22px 0; color: #aab8bf; }
.self-check-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 20px 28px; margin: 0; padding: 20px 22px 22px; }
.self-check-grid .detail--wide { grid-column: 1 / -1; }
.self-check-value { color: var(--self-check-color); font-weight: 650; }
.self-check-boundary { display: grid; grid-template-columns: 180px minmax(0, 1fr) auto; align-items: center; gap: 18px; padding: 15px 22px; background: rgba(7, 11, 14, .52); border-top: 1px solid var(--border); }
.self-check-boundary strong { color: var(--warning); font-size: 12px; }
.self-check-boundary p { margin: 0; color: var(--muted); font-size: 12px; }
.self-check-boundary a { white-space: nowrap; font-size: 11px; }
.browser-attestation { margin: 0 22px 22px; padding: 16px; background: rgba(7, 11, 14, .52); border: 1px solid var(--border); }
.browser-attestation-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; }
.browser-attestation h3 { margin: 0 0 5px; color: #edf5f8; font-size: 13px; font-weight: 650; }
.browser-attestation p { margin: 0; color: var(--muted); font-size: 12px; }
.browser-attestation-status { flex: 0 0 auto; padding: 5px 8px; color: var(--warning); border: 1px solid color-mix(in srgb, var(--warning) 38%, transparent); background: color-mix(in srgb, var(--warning) 10%, transparent); font-size: 10px; font-weight: 700; letter-spacing: .08em; }
.browser-attestation[data-browser-attestation-state="checked"] .browser-attestation-status { color: var(--success); border-color: color-mix(in srgb, var(--success) 38%, transparent); background: color-mix(in srgb, var(--success) 10%, transparent); }
.browser-attestation[data-browser-attestation-state="failed"] .browser-attestation-status { color: var(--danger); border-color: color-mix(in srgb, var(--danger) 38%, transparent); background: color-mix(in srgb, var(--danger) 10%, transparent); }
.browser-attestation-details { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px 20px; margin: 16px 0 0; }
.browser-attestation-details dd { margin: 4px 0 0; color: #cbd8dd; font-size: 11px; overflow-wrap: anywhere; }
.browser-attestation-actions { display: flex; align-items: center; gap: 12px; margin-top: 15px; }
.browser-attestation-actions button { padding: 6px 8px; color: var(--accent); background: transparent; border: 1px solid rgba(99, 220, 255, .25); cursor: pointer; font-size: 11px; }
.browser-attestation-actions button:hover { color: var(--accent-bright); background: var(--accent-soft); }
.browser-attestation-actions button:disabled { color: var(--muted); cursor: wait; opacity: .7; }

.verify-box { margin: 0 0 46px; padding: 22px; border: 1px solid var(--border); background: rgba(14, 21, 27, .38); }
.verify-box-head { display: flex; align-items: baseline; justify-content: space-between; gap: 20px; margin-bottom: 12px; }
.verify-box h2, .section-heading h2 { margin: 0; color: #edf5f8; font-size: 17px; font-weight: 550; }
.verify-box p { max-width: 820px; margin: 0 0 15px; color: #9dadb5; }
.verify-step { margin-top: 22px; }
.verify-step h3 { margin: 0 0 9px; color: #edf5f8; font-size: 14px; font-weight: 600; }
.command-row { display: grid; grid-template-columns: minmax(0, 1fr) auto; border: 1px solid var(--border); background: rgba(7, 11, 14, .72); }
.command-row pre { margin: 0; padding: 14px 16px; overflow: auto; color: #a8c5ce; white-space: pre-wrap; overflow-wrap: anywhere; }
.copy-button, .close-button, .open-target, .tab {
  color: var(--text);
  background: transparent;
  border: 0;
  cursor: pointer;
}
.copy-button { padding: 0 17px; color: #75adbd; border-left: 1px solid var(--border); }
.copy-button:hover { color: #a8d5e0; background: rgba(99, 220, 255, .045); }
.command-note { margin: 10px 0 0 !important; color: var(--muted) !important; font-size: 11px; }

.section-heading { display: flex; align-items: baseline; justify-content: space-between; gap: 20px; margin-bottom: 18px; }
.targets-section { margin-bottom: 48px; }
.target-count { color: var(--muted); font-size: 12px; }
.targets { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }
.target-card { --status-color: var(--muted); min-width: 0; overflow: hidden; background: var(--surface); border: 1px solid var(--border); border-top: 2px solid var(--status-color); transition: border-color .16s ease, transform .16s ease; }
.target-card:hover { border-color: var(--border-strong); transform: translateY(-1px); }
.status-verified { --status-color: var(--success); }
.status-failed { --status-color: var(--danger); }
.status-pending { --status-color: var(--warning); }
.status-unreachable, .status-stale { --status-color: #9da9af; }
.target-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; padding: 20px 22px 18px; background: var(--surface-raised); border-bottom: 1px solid var(--border); }
.target-id { display: block; margin-bottom: 4px; color: var(--muted); font-size: 11px; }
.target-header h3 { margin: 0; color: #f0f6f8; font-size: 18px; font-weight: 550; line-height: 1.25; }
.header-actions { display: flex; align-items: center; gap: 10px; }
.profile-badge { flex: 0 0 auto; padding: 5px 8px; color: var(--accent); background: var(--accent-soft); border: 1px solid rgba(99, 220, 255, .28); font-size: 10px; font-weight: 700; letter-spacing: .08em; }
.status-badge { flex: 0 0 auto; display: inline-flex; align-items: center; gap: 7px; padding: 5px 8px; color: var(--status-color, var(--muted)); background: color-mix(in srgb, var(--status-color, var(--muted)) 12%, transparent); border: 1px solid color-mix(in srgb, var(--status-color, var(--muted)) 42%, transparent); font-size: 10px; font-weight: 700; letter-spacing: .08em; }
.status-badge::before { content: ""; width: 6px; height: 6px; background: currentColor; border-radius: 50%; box-shadow: 0 0 9px currentColor; }
.open-target { padding: 6px 8px; color: var(--accent); border: 1px solid rgba(99, 220, 255, .25); font-size: 11px; }
.open-target:hover { color: var(--accent-bright); background: var(--accent-soft); }
.target-details { display: grid; grid-template-columns: 1fr 1fr; gap: 20px 24px; margin: 0; padding: 22px; }
.detail { min-width: 0; }
.detail--wide { grid-column: 1 / -1; }
code { color: #cbd6db; font: inherit; }
.transport-warning { padding: 10px 12px; background: rgba(232, 200, 114, .06); border: 1px solid rgba(232, 200, 114, .18); }
.transport-warning dt, .transport-warning dd, .transport-warning code { color: var(--warning); }

dialog { width: min(1040px, calc(100% - 32px)); max-height: calc(100vh - 32px); padding: 0; color: var(--text); background: var(--surface); border: 1px solid var(--border-strong); box-shadow: 0 28px 90px rgba(0, 0, 0, .65); }
dialog::backdrop { background: rgba(1, 5, 8, .82); backdrop-filter: blur(5px); }
.inspector-shell { min-height: min(720px, calc(100vh - 34px)); display: grid; grid-template-rows: auto auto 1fr; }
.inspector-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 20px; padding: 24px 26px 20px; background: var(--surface-raised); border-bottom: 1px solid var(--border); }
.panel-kicker { display: block; margin-bottom: 5px; color: var(--accent); }
.inspector-title-row { display: flex; align-items: center; flex-wrap: wrap; gap: 12px; }
.inspector-title-row h2 { margin: 0; color: #f0f7f9; font-size: 22px; font-weight: 550; }
.close-button { padding: 7px 10px; color: var(--muted); border: 1px solid var(--border); }
.close-button:hover { color: var(--text); border-color: var(--border-strong); }
.tabs { display: flex; gap: 0; overflow-x: auto; padding: 0 20px; background: #0a1116; border-bottom: 1px solid var(--border); }
.tab { padding: 14px 16px 12px; color: var(--muted); border-bottom: 2px solid transparent; white-space: nowrap; }
.tab:hover { color: var(--text); }
.tab[aria-selected="true"] { color: var(--accent); border-bottom-color: var(--accent); }
.panel { min-width: 0; padding: 26px; overflow: auto; }
.panel-intro { display: grid; grid-template-columns: 160px minmax(0, 1fr); gap: 24px; margin-bottom: 22px; }
.panel-intro h3 { margin: 0; color: #eef5f7; font-size: 15px; font-weight: 600; }
.panel-intro p { max-width: 760px; margin: 0; color: #9cabb3; }
.panel-intro strong { color: var(--text); }
.panel-links { display: flex; flex-wrap: wrap; gap: 8px; margin: 0 0 16px 184px; }
.panel-links--history { justify-content: flex-end; margin: 0 0 12px; }
.inspector-details { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 20px 26px; margin: 0 0 24px 184px; }
.inspector-details .detail--wide { grid-column: 1 / -1; }
.pcr-panel { margin: 0 0 24px 184px; padding: 14px; background: rgba(7, 11, 14, .46); border: 1px solid var(--border); }
.pcr-panel-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; margin-bottom: 12px; }
.pcr-panel h3 { margin: 0 0 4px; color: #e9f2f5; font-size: 13px; font-weight: 600; }
.pcr-panel p { margin: 0; color: var(--muted); font-size: 11px; }
.pcr-panel-status { flex: 0 0 auto; color: var(--accent); font-size: 10px; font-weight: 700; letter-spacing: .08em; }
.pcr-panel[data-state="verified"] .pcr-panel-status { color: var(--success); }
.pcr-panel[data-state="failed"] .pcr-panel-status { color: var(--danger); }
.pcr-panel[data-state="unavailable"] .pcr-panel-status, .pcr-panel[data-state="error"] .pcr-panel-status { color: var(--warning); }
.pcr-panel .inspector-details { margin: 16px 0; }
.pcr-panel .panel-verify { margin: 0; }
.pcr-table { width: 100%; border-collapse: collapse; table-layout: fixed; }
.pcr-table th, .pcr-table td { padding: 8px 9px; text-align: left; vertical-align: top; border-top: 1px solid var(--border); }
.pcr-table th { color: var(--muted); font-size: 10px; letter-spacing: .08em; text-transform: uppercase; }
.pcr-table th:nth-child(1), .pcr-table td:nth-child(1) { width: 54px; }
.pcr-table th:nth-child(2), .pcr-table td:nth-child(2) { width: 112px; }
.pcr-table th:nth-child(5), .pcr-table td:nth-child(5) { width: 74px; }
.pcr-table code { display: block; color: #b9c9cf; font-size: 10px; line-height: 1.45; overflow-wrap: anywhere; }
.pcr-match { color: var(--muted); font-size: 10px; font-weight: 700; }
.pcr-match[data-match="true"] { color: var(--success); }
.pcr-match[data-match="false"] { color: var(--danger); }
.pcr-match--true { color: var(--success); }
.pcr-match--false { color: var(--danger); }
.artifact-output { min-height: 180px; margin: 0; padding: 18px; overflow: auto; color: #bdcbd1; background: #070b0e; border: 1px solid var(--border); white-space: pre-wrap; overflow-wrap: anywhere; font: 12px/1.58 ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
.artifact-output[data-state="loading"] { color: var(--accent); }
.artifact-output[data-state="error"] { color: var(--danger); border-color: rgba(255, 129, 147, .35); }
.artifact-output table { width: 100%; border-collapse: collapse; white-space: nowrap; }
.artifact-output th, .artifact-output td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }
.artifact-output th { position: sticky; top: 0; color: var(--muted); background: #070b0e; font-size: 10px; letter-spacing: .08em; text-transform: uppercase; }
.history-status { font-weight: 700; }
.history-status-verified { color: var(--success); }
.history-status-failed { color: var(--danger); }
.history-status-pending { color: var(--warning); }
.history-actions { display: flex; align-items: center; gap: 8px; }
.history-actions .copy-button { padding: 5px 7px; white-space: nowrap; }
.history-empty { margin: 0; color: var(--muted); }
.history-pagination { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 14px 12px 0; color: var(--muted); white-space: normal; }
.history-pagination > div { display: flex; gap: 8px; }
.history-page-button { padding: 5px 9px; color: var(--accent); background: transparent; border: 1px solid var(--border); cursor: pointer; }
.history-page-button:hover { color: var(--accent-bright); border-color: var(--border-strong); }
.history-page-button:disabled { color: var(--muted); cursor: default; opacity: .55; }
.history-claims-row > td { padding: 12px !important; background: rgba(99, 220, 255, .025); }
.artifact-output .history-pcr-table { table-layout: fixed; white-space: normal; }
.artifact-output .history-pcr-table td { font-size: 10px; overflow-wrap: anywhere; }
.panel-verify { margin: 0 0 18px 184px; padding: 14px; background: rgba(8, 12, 16, .28); border: 1px solid var(--border); }
.panel-verify h3 { margin: 0 0 6px; color: #cbd7dc; font-size: 13px; font-weight: 600; }
.panel-verify p { margin: 0 0 10px; color: var(--muted); font-size: 12px; }
.deployment-command-box { margin-top: 26px; margin-bottom: 0; }

@media (max-width: 820px) {
  .shell { padding: 42px 18px 58px; }
  .topline { display: block; }
  .raw-nav { justify-content: flex-start; margin-top: 24px; }
  .targets, .self-check-grid, .browser-attestation-details { grid-template-columns: 1fr; }
  .self-check-grid .detail--wide { grid-column: auto; }
  .self-check-boundary { grid-template-columns: 1fr; gap: 7px; }
  .panel-intro { grid-template-columns: 1fr; gap: 8px; }
  .panel-links, .inspector-details, .pcr-panel, .panel-verify { margin-left: 0; }
}

@media (max-width: 520px) {
  .verify-box-head { display: block; }
  .command-row { grid-template-columns: 1fr; }
  .copy-button { min-height: 42px; border-top: 1px solid var(--border-strong); border-left: 0; }
  .target-header { display: block; }
  .header-actions { justify-content: space-between; margin-top: 14px; }
  .target-details, .inspector-details { grid-template-columns: 1fr; }
  .detail--wide, .inspector-details .detail--wide { grid-column: auto; }
  dialog { width: 100%; max-width: none; max-height: 100vh; height: 100vh; border: 0; }
  .inspector-shell { min-height: 100vh; }
  .inspector-head, .panel { padding: 20px 18px; }
  .tabs { padding: 0 6px; }
}
</style>
<script src="/ui.js" defer></script>
</head>
"#;

const INSPECTOR: &str = r##"</main>
<dialog id="target-inspector" aria-labelledby="inspector-title">
  <div class="inspector-shell">
    <header class="inspector-head">
      <div><span class="panel-kicker" id="inspector-kicker"></span><div class="inspector-title-row"><h2 id="inspector-title"></h2><span id="inspector-status" class="status-badge"></span></div></div>
      <button class="close-button" type="button" data-close aria-label="Close target inspector">Close</button>
    </header>
    <nav class="tabs" role="tablist" aria-label="Target information">
      <button class="tab" type="button" role="tab" data-tab="overview" aria-selected="true">Overview</button>
      <button class="tab" type="button" role="tab" data-tab="history" aria-selected="false" tabindex="-1">History</button>
    </nav>
    <section class="panel" data-panel="overview" role="tabpanel">
      <div class="panel-intro"><h3>Current result</h3><p>Canary signs the current result for this target. <strong>VERIFIED</strong> means fresh Nitro evidence matched its configured PCR0/1/2. Verify it locally with <code>canaryctl</code>.</p></div>
      <dl class="inspector-details">
        <div class="detail detail--wide"><dt>Target URL</dt><dd id="inspector-origin"></dd></div>
        <div class="detail"><dt>Result</dt><dd id="inspector-reason"></dd></div>
        <div class="detail"><dt>Observed</dt><dd id="inspector-observed"></dd></div>
        <div class="detail"><dt>Valid until</dt><dd id="inspector-expires"></dd></div>
        <div class="detail"><dt>Transport warning</dt><dd id="inspector-warning"></dd></div>
      </dl>
      <section class="pcr-panel" data-evidence-claims data-state="idle" aria-labelledby="pcr-panel-heading">
        <div class="pcr-panel-head"><div><h3 id="pcr-panel-heading">Authenticated Nitro measurements</h3><p data-evidence-claims-summary>Open a target to load its decoded evidence claims.</p></div><span class="pcr-panel-status" data-evidence-claims-status>WAITING</span></div>
        <table class="pcr-table" data-evidence-claims-table hidden>
          <thead><tr><th scope="col">PCR</th><th scope="col">Meaning</th><th scope="col">Observed</th><th scope="col">Expected</th><th scope="col">Match</th></tr></thead>
          <tbody>
            <tr data-evidence-pcr="0"><th scope="row">PCR0</th><td>Enclave image</td><td><code data-pcr-observed></code></td><td><code data-pcr-expected></code></td><td><span class="pcr-match" data-pcr-match></span></td></tr>
            <tr data-evidence-pcr="1"><th scope="row">PCR1</th><td>Kernel + bootstrap</td><td><code data-pcr-observed></code></td><td><code data-pcr-expected></code></td><td><span class="pcr-match" data-pcr-match></span></td></tr>
            <tr data-evidence-pcr="2"><th scope="row">PCR2</th><td>Application</td><td><code data-pcr-observed></code></td><td><code data-pcr-expected></code></td><td><span class="pcr-match" data-pcr-match></span></td></tr>
          </tbody>
        </table>
      </section>
      <section class="pcr-panel" data-caddy-binding data-state="idle" hidden>
        <div class="pcr-panel-head"><div><h3>Caddy TLS certificate binding</h3><p>The signed attestation metadata is compared with the leaf certificate from the same HTTPS response.</p></div><span class="pcr-panel-status" data-caddy-status></span></div>
        <dl class="inspector-details">
          <div class="detail"><dt>Attested mode</dt><dd><code data-caddy-mode></code></dd></div>
          <div class="detail"><dt>Attested domain</dt><dd><code data-caddy-domain></code></dd></div>
          <div class="detail detail--wide"><dt>Attested certificate SHA-256</dt><dd><code data-caddy-attested-certfp></code></dd></div>
          <div class="detail detail--wide"><dt>Observed certificate SHA-256</dt><dd><code data-caddy-observed-certfp></code></dd></div>
        </dl>
        <div class="panel-verify"><h3>Check the current HTTPS certificate</h3><div class="command-row"><pre id="caddy-certificate-command"></pre><button class="copy-button" type="button" data-copy="#caddy-certificate-command">Copy</button></div></div>
      </section>
      <div class="panel-verify deployment-command-box"><h3>Verify this target locally</h3><div class="command-row"><pre id="deployment-command"></pre><button class="copy-button" type="button" data-copy="#deployment-command">Copy</button></div></div>
      <div class="panel-links"><a class="raw-link" id="statement-json-link" href="#">Statement JSON</a><a class="raw-link" id="evidence-json-link" href="#">Raw evidence JSON</a><a class="raw-link" id="evidence-claims-json-link" href="#">Decoded claims JSON</a></div>
    </section>
    <section class="panel" data-panel="history" role="tabpanel" hidden>
      <div class="panel-intro"><h3>Recorded attempts</h3><p>Use a row’s command to replay that exact signed result locally. Failed transport attempts may not have evidence to replay.</p></div>
      <div class="panel-links panel-links--history"><a class="raw-link" id="history-json-link" href="#">History JSON</a></div>
      <div class="artifact-output" data-artifact-output data-state="idle">Select History to load recorded attempts.</div>
    </section>
  </div>
</dialog>
</body>
</html>"##;

/// Render the public multi-target status page from an immutable snapshot.
pub fn render_status_page(snapshot: &RuntimeSnapshot) -> String {
    let mut page = String::from(PAGE_HEAD);
    page.push_str("<body data-runtime-environment=\"");
    page.push_str(environment_token(snapshot.runtime.environment));
    page.push_str("\" data-identity-mode=\"");
    page.push_str(identity_mode_token(snapshot.runtime.identity_mode));
    page.push_str("\"><main class=\"shell\"><header class=\"intro\"><div class=\"topline\"><div><p class=\"eyebrow\">canaryd</p><h1>Canary status</h1><p class=\"lede\">Canary checks each target’s Nitro attestation against expected PCR0/1/2 and signs the result.</p></div><nav class=\"raw-nav\" aria-label=\"Raw node documents\"><a href=\"/status.json\">Status JSON</a><a href=\"/config.json\">Config JSON</a><a href=\"/keys.json\">Keys JSON</a></nav></div></header>");
    page.push_str("<section class=\"targets-section\" aria-labelledby=\"targets-heading\"><div class=\"section-heading\"><h2 id=\"targets-heading\">Targets</h2><span class=\"target-count\">");
    page.push_str(&snapshot.targets.len().to_string());
    page.push_str(if snapshot.targets.len() == 1 {
        " target"
    } else {
        " targets"
    });
    page.push_str("</span></div><div class=\"targets\">");

    for target in &snapshot.targets {
        let is_caddy = target.statement.payload.claim_type == CADDY_CLAIM_TYPE;
        let tls = target.statement.payload.tls.as_ref();
        page.push_str("<article class=\"target-card ");
        page.push_str(status_class(target.status));
        page.push_str("\" data-target-id=\"");
        push_escaped(&mut page, &target.id);
        page.push_str("\" data-target-name=\"");
        push_escaped(&mut page, &target.name);
        page.push_str("\" data-target-origin=\"");
        push_escaped(&mut page, &target.target_origin);
        page.push_str("\" data-target-status=\"");
        push_escaped(&mut page, status_text(target.status));
        page.push_str("\" data-target-reason=\"");
        push_escaped(&mut page, &target.reason);
        page.push_str("\" data-target-observed=\"");
        if let Some(observed) = target.observed_at {
            push_escaped(&mut page, &observed.to_rfc3339());
        }
        page.push_str("\" data-target-expires=\"");
        push_escaped(&mut page, &target.expires_at.to_rfc3339());
        page.push_str("\" data-target-warning=\"");
        if let Some(warning) = &target.transport_warning {
            push_escaped(&mut page, warning);
        }
        if is_caddy {
            page.push_str("\" data-target-profile=\"caddy\" data-tls-mode=\"");
            if let Some(tls) = tls {
                push_escaped(&mut page, &tls.attested_mode);
            }
            page.push_str("\" data-tls-domain=\"");
            if let Some(tls) = tls {
                push_escaped(&mut page, &tls.attested_domain);
            }
            page.push_str("\" data-tls-attested-certfp=\"");
            if let Some(tls) = tls {
                push_escaped(&mut page, &tls.attested_certfp);
            }
            page.push_str("\" data-tls-observed-certfp=\"");
            if let Some(tls) = tls {
                push_escaped(&mut page, &tls.observed_certfp);
            }
        }
        page.push_str("\"><header class=\"target-header\"><div><span class=\"target-id\">");
        push_escaped(&mut page, &target.id);
        page.push_str("</span><h3>");
        push_escaped(&mut page, &target.name);
        page.push_str("</h3></div><div class=\"header-actions\">");
        if is_caddy {
            page.push_str("<span class=\"profile-badge\">E2E · CADDY</span>");
        }
        page.push_str("<span class=\"status-badge ");
        page.push_str(status_class(target.status));
        page.push_str("\">");
        push_escaped(&mut page, status_text(target.status));
        page.push_str("</span><button class=\"open-target\" type=\"button\" data-open-target aria-haspopup=\"dialog\">Inspect →</button></div></header><dl class=\"target-details\"><div class=\"detail detail--wide\"><dt>Target URL</dt><dd><code>");
        push_escaped(&mut page, &target.target_origin);
        page.push_str("</code></dd></div><div class=\"detail\"><dt>Last check</dt><dd>");
        if let Some(observed) = target.observed_at {
            push_escaped(&mut page, &observed.to_rfc3339());
        } else {
            page.push('—');
        }
        page.push_str("</dd></div><div class=\"detail\"><dt>Valid until</dt><dd>");
        push_escaped(&mut page, &target.expires_at.to_rfc3339());
        page.push_str("</dd></div>");
        if let Some(tls) = tls {
            page.push_str(
                "<div class=\"detail detail--wide\"><dt>Observed TLS cert SHA-256</dt><dd><code>",
            );
            push_escaped(&mut page, &tls.observed_certfp);
            page.push_str("</code></dd></div>");
        }
        if target.status != canary_core::statement::Status::Verified {
            page.push_str(
                "<div class=\"detail detail--wide transport-warning\"><dt>Result</dt><dd><code>",
            );
            push_escaped(&mut page, &target.reason);
            page.push_str("</code></dd></div>");
        }
        if let Some(warning) = &target.transport_warning {
            page.push_str("<div class=\"detail detail--wide transport-warning\"><dt>Transport warning</dt><dd><code>");
            push_escaped(&mut page, warning);
            page.push_str("</code></dd></div>");
        }
        page.push_str("</dl></article>");
    }

    page.push_str("</div></section>");
    push_verification_guide(
        &mut page,
        snapshot.runtime.environment,
        snapshot.runtime.identity_mode,
    );
    push_self_check(&mut page, snapshot);
    page.push_str(INSPECTOR);
    page
}

fn push_self_check(page: &mut String, snapshot: &RuntimeSnapshot) {
    let is_enclave = snapshot.runtime.environment == ExecutionEnvironment::NitroEnclave;
    page.push_str("<section class=\"self-check");
    if is_enclave {
        page.push_str(" self-check--enclave");
    }
    page.push_str("\" aria-labelledby=\"self-check-heading\"><header class=\"self-check-head\"><div><span class=\"self-check-kicker\">Node details</span><h2 id=\"self-check-heading\">Canary runtime details</h2></div><span class=\"self-check-badge\">");
    page.push_str(if is_enclave {
        "NSM DETECTED"
    } else {
        "LOCAL RUNTIME"
    });
    page.push_str("</span></header><p class=\"self-check-summary\">");
    page.push_str(if is_enclave {
        "This process can access the AWS Nitro Security Module. The service is ready and publishing an immutable runtime identity."
    } else {
        "No AWS Nitro Security Module is visible. The service is ready, but its initial identity and measured configuration are not remotely attested."
    });
    page.push_str("</p><dl class=\"self-check-grid\"><div class=\"detail\"><dt>Node</dt><dd>");
    push_escaped(page, &snapshot.node_id);
    page.push_str("</dd></div><div class=\"detail\"><dt>Last updated</dt><dd>");
    push_escaped(page, &snapshot.generated_at.to_rfc3339());
    page.push_str(
        "</dd></div><div class=\"detail\"><dt>Execution environment</dt><dd class=\"self-check-value\">",
    );
    page.push_str(environment_label(snapshot.runtime.environment));
    page.push_str("</dd></div><div class=\"detail\"><dt>Service</dt><dd class=\"self-check-value\">READY</dd></div><div class=\"detail\"><dt>Identity</dt><dd>");
    page.push_str(identity_mode_label(snapshot.runtime.identity_mode));
    page.push_str(
        "</dd></div><div class=\"detail detail--wide\"><dt>Running binary</dt><dd><code>",
    );
    push_escaped(page, &snapshot.runtime.binary_digest);
    page.push_str(
        "</code></dd></div><div class=\"detail detail--wide\"><dt>Config digest</dt><dd><code>",
    );
    push_escaped(page, &snapshot.config_digest);
    page.push_str("</code></dd></div></dl>");
    if is_enclave {
        page.push_str("<section class=\"browser-attestation\" data-browser-attestation data-browser-attestation-state=\"idle\" aria-labelledby=\"browser-attestation-heading\"><div class=\"browser-attestation-head\"><div><h3 id=\"browser-attestation-heading\">Browser evidence check</h3><p data-browser-attestation-summary>Not run. Start this convenience check to request fresh Nitro evidence.</p></div><span class=\"browser-attestation-status\" data-browser-attestation-status>NOT RUN</span></div><dl class=\"browser-attestation-details\" data-browser-attestation-pcrs hidden><div class=\"detail\"><dt>PCR0 · image</dt><dd><code data-browser-pcr=\"PCR0\"></code></dd></div><div class=\"detail\"><dt>PCR1 · kernel</dt><dd><code data-browser-pcr=\"PCR1\"></code></dd></div><div class=\"detail\"><dt>PCR2 · application</dt><dd><code data-browser-pcr=\"PCR2\"></code></dd></div></dl><div class=\"browser-attestation-actions\"><button type=\"button\" data-browser-attestation-run>Run browser evidence check</button><p>This page and JavaScript are served by the same origin being checked. The check validates certificate signatures to the pinned AWS root, certificate dates, COSE ES384, and a fresh nonce. It does not perform full X.509 policy validation or compare independently supplied expected Canary PCR policy; use <code>canaryctl save-canary-keys</code> for the full independent check.</p></div></section>");
    }
    page.push_str(
        "<div class=\"self-check-boundary\"><strong>External verification required</strong><p>",
    );
    page.push_str(if is_enclave {
        "NSM detection is self-reported. canaryctl verifies fresh nonce-bound Nitro evidence, expected Canary PCR0/1/2, and the attested config and key bindings."
    } else {
        "Use the explicit local TOFU workflow only for development. It verifies signer continuity and target evidence, but the initial Canary identity and policy remain TOFU."
    });
    page.push_str("</p><a href=\"#verify-heading\">Independent verification ↑</a></div></section>");
}

fn push_verification_guide(
    page: &mut String,
    environment: ExecutionEnvironment,
    identity_mode: IdentityMode,
) {
    page.push_str("<section class=\"verify-box\" aria-labelledby=\"verify-heading\"><div class=\"verify-box-head\"><h2 id=\"verify-heading\">Verify independently</h2></div>");
    match environment {
        ExecutionEnvironment::NitroEnclave => {
            page.push_str("<p><strong>ATTESTED:</strong> Canary’s fresh Nitro evidence matched operator-supplied Canary PCR0/1/2 and bound its config and keys.</p><div class=\"verify-step\"><h3>1. Verify and save Canary keys</h3><p><code>canaryctl save-canary-keys</code> writes <code>canary-keys.json</code> only after fresh Canary attestation, expected PCR0/1/2, and the attested config/key binding all verify successfully.</p><div class=\"command-row\"><pre id=\"save-keys-command\">caution verify --save-pcrs\n\n# Verifies fresh Canary attestation + expected PCR0/1/2, then saves the authenticated keys.\ncanaryctl save-canary-keys --canary-url &lt;this-origin&gt; --expected-pcrs .caution/trusted_hashes.json --output canary-keys.json</pre><button class=\"copy-button\" type=\"button\" data-copy=\"#save-keys-command\">Copy</button></div></div><div class=\"verify-step\"><h3>2. Verify every target</h3><div class=\"command-row\"><pre id=\"all-targets-command\">canaryctl verify --canary-url &lt;this-origin&gt; --expected-pcrs .caution/trusted_hashes.json</pre><button class=\"copy-button\" type=\"button\" data-copy=\"#all-targets-command\">Copy</button></div></div>");
        }
        ExecutionEnvironment::NonEnclave => {
            page.push_str("<p><strong>TOFU:</strong> signatures and target evidence are checked, but Canary’s initial identity and config authenticity are not established.</p><div class=\"verify-step\"><h3>1. Save Canary’s observed keys</h3><p><code>canaryctl save-canary-keys</code> saves the observed TOFU keys to <code>canary-keys.json</code>; Canary attestation is intentionally skipped in this local workflow.</p><div class=\"command-row\"><pre id=\"save-keys-command\"># Saves observed TOFU keys; Canary attestation is skipped.\ncanaryctl save-canary-keys --canary-url &lt;this-origin&gt; --skip-canary-attestation --allow-http --output canary-keys.json</pre><button class=\"copy-button\" type=\"button\" data-copy=\"#save-keys-command\">Copy</button></div></div><div class=\"verify-step\"><h3>2. Verify every target</h3><div class=\"command-row\"><pre id=\"all-targets-command\">canaryctl verify --canary-url &lt;this-origin&gt; --skip-canary-attestation --allow-http</pre><button class=\"copy-button\" type=\"button\" data-copy=\"#all-targets-command\">Copy</button></div></div>");
        }
    }
    if identity_mode == IdentityMode::Ephemeral {
        page.push_str("<p class=\"command-note\">This Canary identity is ephemeral; save its new keys after restart.</p>");
    }
    page.push_str("</section>");
}

fn identity_mode_token(mode: IdentityMode) -> &'static str {
    match mode {
        IdentityMode::Stable => "stable",
        IdentityMode::Ephemeral => "ephemeral",
    }
}

fn identity_mode_label(mode: IdentityMode) -> &'static str {
    match mode {
        IdentityMode::Stable => "Stable identity",
        IdentityMode::Ephemeral => "Ephemeral identity",
    }
}

fn environment_token(environment: ExecutionEnvironment) -> &'static str {
    match environment {
        ExecutionEnvironment::NitroEnclave => "nitro_enclave",
        ExecutionEnvironment::NonEnclave => "non_enclave",
    }
}

fn environment_label(environment: ExecutionEnvironment) -> &'static str {
    match environment {
        ExecutionEnvironment::NitroEnclave => "Nitro enclave detected",
        ExecutionEnvironment::NonEnclave => "Non-enclave runtime",
    }
}

fn status_class(status: canary_core::statement::Status) -> &'static str {
    match status {
        canary_core::statement::Status::Verified => "status-verified",
        canary_core::statement::Status::Failed => "status-failed",
        canary_core::statement::Status::Pending => "status-pending",
        canary_core::statement::Status::Unreachable => "status-unreachable",
        canary_core::statement::Status::Stale => "status-stale",
    }
}

fn status_text(status: canary_core::statement::Status) -> &'static str {
    match status {
        canary_core::statement::Status::Verified => "VERIFIED",
        canary_core::statement::Status::Failed => "FAILED",
        canary_core::statement::Status::Pending => "PENDING",
        canary_core::statement::Status::Unreachable => "UNREACHABLE",
        canary_core::statement::Status::Stale => "STALE",
    }
}

fn push_escaped(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#x27;"),
            _ => output.push(character),
        }
    }
}
