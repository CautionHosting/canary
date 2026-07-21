//! Server-rendered public status page with a small same-origin artifact explorer.
//!
//! Configuration-derived strings are HTML-escaped. The static client script
//! fetches only the existing read-only JSON endpoints and never treats the UI
//! as an independent cryptographic verifier.

use canary_core::node::IdentityMode;

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
.eyebrow, .label, dt, .guide-number, .panel-kicker {
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
.raw-nav a, .actions a, .raw-link {
  padding: 7px 9px;
  color: var(--accent);
  text-decoration: none;
  border: 1px solid var(--border);
  background: rgba(8, 12, 16, .55);
  font-size: 11px;
}
.raw-nav a:hover, .actions a:hover, .raw-link:hover { background: var(--accent-soft); border-color: rgba(99, 220, 255, .32); }

.node-meta { display: grid; grid-template-columns: minmax(180px, .55fr) minmax(240px, 1fr); gap: 18px 32px; margin: 34px 0 22px; }
.meta-item { min-width: 0; }
.meta-item--wide { grid-column: 1 / -1; }
.label, dt { display: block; margin: 0 0 5px; }
.value, dd { min-width: 0; margin: 0; overflow-wrap: anywhere; color: #cbd7dc; }
.environment { display: inline-flex; align-items: center; gap: 7px; color: var(--warning); }
.environment::before { content: ""; width: 7px; height: 7px; border-radius: 50%; background: currentColor; box-shadow: 0 0 9px currentColor; }
.environment--enclave { color: var(--success); }

.trust-note { display: grid; grid-template-columns: 170px 1fr; gap: 20px; padding: 16px 18px; border: 1px solid rgba(232, 200, 114, .2); border-left: 2px solid var(--warning); background: rgba(232, 200, 114, .045); }
.trust-note strong { color: var(--warning); font-weight: 650; }
.trust-note p { margin: 0; color: #aab7be; }

.verify-box { margin: 0 0 46px; padding: 22px; border: 1px solid rgba(99, 220, 255, .25); background: linear-gradient(135deg, rgba(99, 220, 255, .07), rgba(14, 21, 27, .6)); }
.verify-box-head { display: flex; align-items: baseline; justify-content: space-between; gap: 20px; margin-bottom: 12px; }
.verify-box h2, .section-heading h2 { margin: 0; color: #edf5f8; font-size: 17px; font-weight: 550; }
.verify-box p { max-width: 820px; margin: 0 0 15px; color: #9dadb5; }
.verify-step { margin-top: 22px; }
.verify-step h3 { margin: 0 0 9px; color: #edf5f8; font-size: 14px; font-weight: 600; }
.verification-layers { margin: 18px 0 0; padding-left: 22px; color: #9dadb5; }
.verification-layers li { margin: 7px 0; padding-left: 5px; }
.verification-layers strong { color: var(--text); }
.command-row { display: grid; grid-template-columns: minmax(0, 1fr) auto; border: 1px solid var(--border-strong); background: #070b0e; }
.command-row pre { margin: 0; padding: 14px 16px; overflow: auto; color: var(--accent-bright); white-space: pre-wrap; overflow-wrap: anywhere; }
.copy-button, .close-button, .open-target, .tab {
  color: var(--text);
  background: transparent;
  border: 0;
  cursor: pointer;
}
.copy-button { padding: 0 17px; color: var(--accent); border-left: 1px solid var(--border-strong); }
.copy-button:hover { background: var(--accent-soft); }
.command-note { margin: 10px 0 0 !important; color: var(--muted) !important; font-size: 11px; }

.artifact-guide { display: grid; grid-template-columns: repeat(3, 1fr); margin-bottom: 48px; border: 1px solid var(--border); }
.guide-item { min-width: 0; padding: 20px; background: rgba(14, 21, 27, .55); }
.guide-item + .guide-item { border-left: 1px solid var(--border); }
.guide-number { color: var(--accent); }
.guide-item h2 { margin: 8px 0 7px; color: #edf5f8; font-size: 15px; font-weight: 600; }
.guide-item p { margin: 0; color: #91a1a9; font-size: 12px; }

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
.actions { display: flex; flex-wrap: wrap; gap: 6px; padding: 14px 16px; background: var(--surface-soft); border-top: 1px solid var(--border); }

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
.inspector-details { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 20px 26px; margin: 0 0 24px 184px; }
.inspector-details .detail--wide { grid-column: 1 / -1; }
.artifact-output { min-height: 180px; margin: 0; padding: 18px; overflow: auto; color: #bdcbd1; background: #070b0e; border: 1px solid var(--border); white-space: pre-wrap; overflow-wrap: anywhere; font: 12px/1.58 ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
.artifact-output[data-state="loading"] { color: var(--accent); }
.artifact-output[data-state="error"] { color: var(--danger); border-color: rgba(255, 129, 147, .35); }
.artifact-output table { width: 100%; border-collapse: collapse; white-space: nowrap; }
.artifact-output th, .artifact-output td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }
.artifact-output th { position: sticky; top: 0; color: var(--muted); background: #070b0e; font-size: 10px; letter-spacing: .08em; text-transform: uppercase; }
.digest-cell { max-width: 280px; overflow: hidden; text-overflow: ellipsis; }
.history-status { font-weight: 700; }
.history-status-verified { color: var(--success); }
.history-status-failed { color: var(--danger); }
.history-status-pending { color: var(--warning); }
.history-actions { display: flex; align-items: center; gap: 8px; }
.history-actions .copy-button { padding: 5px 7px; white-space: nowrap; }
.target-command-box { margin: 26px 0 0 184px; }
.target-command-box h3 { margin: 0 0 10px; color: #eef5f7; font-size: 13px; font-weight: 600; }

@media (max-width: 820px) {
  .shell { padding: 42px 18px 58px; }
  .topline { display: block; }
  .raw-nav { justify-content: flex-start; margin-top: 24px; }
  .node-meta, .targets, .artifact-guide { grid-template-columns: 1fr; }
  .artifact-guide { border: 0; gap: 10px; }
  .guide-item { border: 1px solid var(--border); }
  .guide-item + .guide-item { border-left: 1px solid var(--border); }
  .meta-item--wide { grid-column: auto; }
  .panel-intro { grid-template-columns: 1fr; gap: 8px; }
  .panel-links, .inspector-details, .target-command-box { margin-left: 0; }
}

@media (max-width: 520px) {
  .trust-note { grid-template-columns: 1fr; gap: 7px; }
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
      <button class="tab" type="button" role="tab" data-tab="target" aria-selected="true">Target</button>
      <button class="tab" type="button" role="tab" data-tab="statement" aria-selected="false" tabindex="-1">Statement</button>
      <button class="tab" type="button" role="tab" data-tab="evidence" aria-selected="false" tabindex="-1">Evidence</button>
      <button class="tab" type="button" role="tab" data-tab="history" aria-selected="false" tabindex="-1">History</button>
    </nav>
    <section class="panel" data-panel="target" role="tabpanel">
      <div class="panel-intro"><h3>What you are seeing</h3><p>This is Canary’s <strong>current server-side conclusion</strong> for one configured target. The dashboard presents that conclusion; it does not independently verify signatures or Nitro evidence in your browser.</p></div>
      <dl class="inspector-details">
        <div class="detail detail--wide"><dt>Attested target origin</dt><dd id="inspector-origin"></dd></div>
        <div class="detail"><dt>Signed reason</dt><dd id="inspector-reason"></dd></div>
        <div class="detail"><dt>Observed</dt><dd id="inspector-observed"></dd></div>
        <div class="detail"><dt>Claim expires</dt><dd id="inspector-expires"></dd></div>
        <div class="detail"><dt>Transport warning</dt><dd id="inspector-warning"></dd></div>
      </dl>
      <div class="target-command-box"><h3>Verify this target independently</h3><div class="command-row"><pre id="target-command"></pre><button class="copy-button" type="button" data-copy="#target-command">Copy</button></div></div>
    </section>
    <section class="panel" data-panel="statement" role="tabpanel" hidden>
      <div class="panel-intro"><h3>Canary’s signed claim</h3><p>The statement says <strong>what Canary concluded</strong>. Its Ed25519 and ML-DSA-65 signatures cover the target identity, result, config digest, evidence digest, observation time, expiry, verifier identity, and key epoch. A valid signature authenticates the claim; it does not replace checking the linked evidence.</p></div>
      <div class="panel-links"><a class="raw-link" id="statement-json-link" href="#">Open raw statement JSON</a></div>
      <pre class="artifact-output" data-artifact-output data-state="idle">Select this view to load its current JSON.</pre>
    </section>
    <section class="panel" data-panel="evidence" role="tabpanel" hidden>
      <div class="panel-intro"><h3>The underlying proof material</h3><p>Evidence is <strong>the target’s raw Bootproof/Nitro attestation bundle</strong>, including the nonce and document Canary checked against configured PCR0/1/2. It is not Canary’s conclusion. The signed statement binds its digest and observation time so the two artifacts cannot be silently mixed. Raw Nitro evidence can expose infrastructure metadata.</p></div>
      <div class="panel-links"><a class="raw-link" id="evidence-json-link" href="#">Open raw evidence JSON</a></div>
      <pre class="artifact-output" data-artifact-output data-state="idle">Select this view to load its current JSON.</pre>
    </section>
    <section class="panel" data-panel="history" role="tabpanel" hidden>
      <div class="panel-intro"><h3>Recorded attempts and replay</h3><p>History summaries are <strong>unsigned diagnostic data</strong>, but each decodable attempt retains its exact signed statement and nonce-bound evidence. Open an attempt’s artifacts or copy its <code>canaryctl verify-history</code> command to reproduce the cryptographic result locally. Transport and undecodable-response failures have no target evidence to replay.</p></div>
      <div class="panel-links"><a class="raw-link" id="history-json-link" href="#">Open raw history JSON</a></div>
      <div class="artifact-output" data-artifact-output data-state="idle">Select this view to load its current JSON.</div>
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
    page.push_str("\"><main class=\"shell\"><header class=\"intro\"><div class=\"topline\"><div><p class=\"eyebrow\">canaryd / ");
    push_escaped(&mut page, &snapshot.runtime.binary_digest);
    page.push_str("</p><h1>Canary status</h1><p class=\"lede\">Fresh Nitro attestation checks, short-lived signed claims, and the proof material behind them.</p></div><nav class=\"raw-nav\" aria-label=\"Raw node documents\"><a href=\"/status.json\">Status JSON</a><a href=\"/config.json\">Config JSON</a><a href=\"/keys.json\">Keys JSON</a></nav></div><div class=\"node-meta\"><div class=\"meta-item\"><span class=\"label\">Node</span><div class=\"value\">");
    push_escaped(&mut page, &snapshot.node_id);
    page.push_str("</div></div><div class=\"meta-item\"><span class=\"label\">Execution environment</span><div class=\"environment ");
    if snapshot.runtime.environment == ExecutionEnvironment::NitroEnclave {
        page.push_str("environment--enclave");
    }
    page.push_str("\">");
    page.push_str(environment_label(snapshot.runtime.environment));
    page.push_str("</div></div><div class=\"meta-item\"><span class=\"label\">Identity lifecycle</span><div class=\"value\">");
    page.push_str(identity_mode_label(snapshot.runtime.identity_mode));
    page.push_str("</div></div><div class=\"meta-item\"><span class=\"label\">Snapshot</span><div class=\"value\">");
    push_escaped(&mut page, &snapshot.generated_at.to_rfc3339());
    page.push_str("</div></div><div class=\"meta-item meta-item--wide\"><span class=\"label\">Running binary</span><div class=\"value\">");
    push_escaped(&mut page, &snapshot.runtime.binary_digest);
    page.push_str("</div></div><div class=\"meta-item meta-item--wide\"><span class=\"label\">Config digest</span><div class=\"value\">");
    push_escaped(&mut page, &snapshot.config_digest);
    page.push_str("</div></div></div><div class=\"trust-note\" role=\"note\"><strong>How to read this page</strong><p>");
    page.push_str(environment_trust_note(snapshot.runtime.environment));
    page.push(' ');
    page.push_str(identity_mode_note(snapshot.runtime.identity_mode));
    page.push_str(" The badges are Canary’s server-side conclusions; this browser does not verify their signatures or evidence.</p></div></header>");
    page.push_str("<section class=\"targets-section\" aria-labelledby=\"targets-heading\"><div class=\"section-heading\"><h2 id=\"targets-heading\">Monitored targets</h2><span class=\"target-count\">");
    page.push_str(&snapshot.targets.len().to_string());
    page.push_str(if snapshot.targets.len() == 1 {
        " target"
    } else {
        " targets"
    });
    page.push_str("</span></div><div class=\"targets\">");

    for target in &snapshot.targets {
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
        page.push_str("\"><header class=\"target-header\"><div><span class=\"target-id\">");
        push_escaped(&mut page, &target.id);
        page.push_str("</span><h3>");
        push_escaped(&mut page, &target.name);
        page.push_str("</h3></div><div class=\"header-actions\"><span class=\"status-badge ");
        page.push_str(status_class(target.status));
        page.push_str("\">");
        push_escaped(&mut page, status_text(target.status));
        page.push_str("</span><button class=\"open-target\" type=\"button\" data-open-target aria-haspopup=\"dialog\">Inspect →</button></div></header><dl class=\"target-details\"><div class=\"detail detail--wide\"><dt>Attested target</dt><dd><code>");
        push_escaped(&mut page, &target.target_origin);
        page.push_str("</code></dd></div><div class=\"detail\"><dt>Reason</dt><dd><code>");
        push_escaped(&mut page, &target.reason);
        page.push_str("</code></dd></div><div class=\"detail\"><dt>Expires</dt><dd>");
        push_escaped(&mut page, &target.expires_at.to_rfc3339());
        page.push_str("</dd></div>");
        if let Some(warning) = &target.transport_warning {
            page.push_str("<div class=\"detail detail--wide transport-warning\"><dt>Transport warning</dt><dd><code>");
            push_escaped(&mut page, warning);
            page.push_str("</code></dd></div>");
        }
        page.push_str(
            "</dl><nav class=\"actions\" aria-label=\"Raw target JSON\"><a href=\"/targets/",
        );
        push_escaped(&mut page, &target.id);
        page.push_str("/statement\">Statement JSON</a><a href=\"/targets/");
        push_escaped(&mut page, &target.id);
        page.push_str("/evidence\">Evidence JSON</a><a href=\"/targets/");
        push_escaped(&mut page, &target.id);
        page.push_str("/history\">History JSON</a></nav></article>");
    }

    page.push_str("</div></section>");
    page.push_str("<section class=\"artifact-guide\" aria-label=\"Artifact guide\"><article class=\"guide-item\"><span class=\"guide-number\">01 / Claim</span><h2>Statement</h2><p>Canary’s short-lived, hybrid-signed conclusion. It binds the target, policy config, result, evidence digest, and time.</p></article><article class=\"guide-item\"><span class=\"guide-number\">02 / Proof</span><h2>Evidence</h2><p>The raw nonce-bound Nitro material Canary evaluated. It proves nothing about Canary’s conclusion until linked and checked.</p></article><article class=\"guide-item\"><span class=\"guide-number\">03 / Diagnostics</span><h2>History</h2><p>Unsigned process-lifetime observations for understanding changes. Useful context, not durable cryptographic proof.</p></article></section>");
    push_verification_guide(
        &mut page,
        snapshot.runtime.environment,
        snapshot.runtime.identity_mode,
    );
    page.push_str(INSPECTOR);
    page
}

fn push_verification_guide(
    page: &mut String,
    environment: ExecutionEnvironment,
    identity_mode: IdentityMode,
) {
    page.push_str("<section class=\"verify-box\" aria-labelledby=\"verify-heading\"><div class=\"verify-box-head\"><h2 id=\"verify-heading\">Verify independently</h2></div>");
    match environment {
        ExecutionEnvironment::NitroEnclave => {
            page.push_str("<p>A Nitro device is visible to this process. Treat that only as a runtime hint: the attested flow below is what proves the Canary workload and its measured configuration from outside the enclave. ");
            page.push_str(identity_mode_note(identity_mode));
            page.push_str("</p><div class=\"verify-step\"><h3>1. Reproduce Canary PCRs and enroll its signing keys</h3><p><code>inspect-node</code> requests a fresh nonce-bound Canary attestation, checks its PCR0/1/2, config digest, keyset digest and identity lifecycle, then saves the exact public keys without overwriting an existing pin.</p><div class=\"command-row\"><pre id=\"enroll-command\">caution verify --save-pcrs\ncanaryctl inspect-node --url &lt;this-origin&gt; --pcrs-file .caution/trusted_hashes.json --keys-out canary-keys.json</pre><button class=\"copy-button\" type=\"button\" data-copy=\"#enroll-command\">Copy</button></div></div><div class=\"verify-step\"><h3>2. Verify the node and every monitored target</h3><p>This checks each current published signed claim, not the complete attempt history. The CLI prints its signed observation, issuance and expiry times; use <code>verify-history</code> for one exact past attempt.</p><div class=\"command-row\"><pre id=\"all-targets-command\">canaryctl verify --url &lt;this-origin&gt; --pcrs-file .caution/trusted_hashes.json --keys canary-keys.json</pre><button class=\"copy-button\" type=\"button\" data-copy=\"#all-targets-command\">Copy</button></div><ol class=\"verification-layers\"><li><strong>Canary identity:</strong> fresh AWS/Nitro chain, COSE signature, nonce and exact Canary PCR0/1/2.</li><li><strong>Measured policy and keys:</strong> attested config/keyset digests plus exact equality with <code>canary-keys.json</code>.</li><li><strong>Signed claim:</strong> mandatory Ed25519 and ML-DSA-65 signatures, freshness, node, target and config binding.</li><li><strong>Target proof:</strong> exact statement/evidence digest link, then independent replay of the target Nitro evidence, nonce and configured target PCR0/1/2.</li></ol></div><p class=\"command-note\">The executable hash above identifies the bytes running here, but the independently reproduced Canary PCRs—not this self-reported page—establish workload identity.</p>");
        }
        ExecutionEnvironment::NonEnclave => {
            page.push_str("<p>No Nitro device is visible to this process, so Canary cannot offer its own hardware-backed workload identity. The development flow keeps all target verification but makes the initial signing-key enrollment explicit trust on first use (TOFU).</p><div class=\"verify-step\"><h3>1. Enroll the initially observed signing keys</h3><p>Review the endpoint you are connected to, then save its exact public keys. Protect this public file from modification.</p><div class=\"command-row\"><pre id=\"enroll-command\">canaryctl inspect-node --url &lt;this-origin&gt; --insecure --keys-out canary-keys.json</pre><button class=\"copy-button\" type=\"button\" data-copy=\"#enroll-command\">Copy</button></div></div><div class=\"verify-step\"><h3>2. Verify signer continuity and every monitored target</h3><p>This checks each current published signed claim, not the complete attempt history. The CLI prints its signed observation, issuance and expiry times; use <code>verify-history</code> for one exact past attempt.</p><div class=\"command-row\"><pre id=\"all-targets-command\">canaryctl verify --url &lt;this-origin&gt; --insecure --keys canary-keys.json</pre><button class=\"copy-button\" type=\"button\" data-copy=\"#all-targets-command\">Copy</button></div><ol class=\"verification-layers\"><li><strong>Canary identity:</strong> not verified; there is no Canary attestation or Canary PCR check.</li><li><strong>Signer continuity:</strong> live keys must exactly match the TOFU-enrolled <code>canary-keys.json</code>.</li><li><strong>Signed claim:</strong> both Ed25519 and ML-DSA-65 signatures and all statement/config/evidence links are checked.</li><li><strong>Target proof:</strong> target Nitro evidence, nonce and configured target PCR0/1/2 are still independently replayed.</li></ol></div><p class=\"command-note\">This detects later key substitution but cannot prove who controlled the endpoint during enrollment, that the initial config or configured target PCR policy was authentic, or that canaryd is reviewed code.</p>");
        }
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

fn identity_mode_note(mode: IdentityMode) -> &'static str {
    match mode {
        IdentityMode::Stable => {
            "The external master seed keeps the signing identity stable across restarts."
        }
        IdentityMode::Ephemeral => {
            "The signing keys were generated for this process and change on restart; re-enroll a new key file after every restart."
        }
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
        ExecutionEnvironment::NonEnclave => "Non-enclave runtime detected",
    }
}

fn environment_trust_note(environment: ExecutionEnvironment) -> &'static str {
    match environment {
        ExecutionEnvironment::NitroEnclave => {
            "The local /dev/nsm check reports a Nitro enclave, but that is not remote proof. Verify the fresh Canary attestation and expected PCRs with canaryctl."
        }
        ExecutionEnvironment::NonEnclave => {
            "No Nitro NSM device was detected. Use the explicitly insecure development workflow and treat its first key enrollment as TOFU."
        }
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
