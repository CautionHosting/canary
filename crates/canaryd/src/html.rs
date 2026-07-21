//! Deliberately small, server-rendered public status page.
//!
//! The page has no client-side code. Every string interpolated into it is
//! escaped so target configuration cannot become executable HTML.

use crate::model::RuntimeSnapshot;

const PAGE_HEAD: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>Canary status</title>
<style>
:root {
  --bg: #090d11;
  --surface: #0f151b;
  --surface-raised: #121a21;
  --border: #25323b;
  --border-strong: #344650;
  --text: #d9e3e8;
  --muted: #81919b;
  --accent: #63dcff;
  --accent-soft: rgba(99, 220, 255, .1);
  --danger: #ff7f91;
  --warning: #e8c872;
}

* { box-sizing: border-box; }

html { background: var(--bg); }

body {
  min-width: 280px;
  min-height: 100vh;
  margin: 0;
  color: var(--text);
  background:
    linear-gradient(180deg, rgba(99, 220, 255, .035), transparent 260px),
    var(--bg);
  font: 15px/1.55 ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
  -webkit-font-smoothing: antialiased;
}

a { color: var(--accent); }
a:hover { color: #b9f1ff; }
a:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; }

.shell {
  width: min(1120px, 100%);
  margin: 0 auto;
  padding: 68px 28px 80px;
}

.eyebrow {
  margin: 0 0 10px;
  color: var(--accent);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: .16em;
  text-transform: uppercase;
}

h1 {
  margin: 0;
  color: #f2f7f9;
  font-size: clamp(32px, 5vw, 48px);
  font-weight: 500;
  letter-spacing: -.045em;
  line-height: 1.05;
}

.intro {
  margin-bottom: 44px;
  padding-bottom: 34px;
  border-bottom: 1px solid var(--border);
}

.node-meta {
  display: grid;
  grid-template-columns: minmax(180px, .65fr) minmax(240px, 1fr);
  gap: 18px 32px;
  margin: 32px 0 20px;
}

.meta-item { min-width: 0; }
.meta-item--wide { grid-column: 1 / -1; }

.label,
dt {
  margin: 0 0 5px;
  color: var(--muted);
  font-size: 11px;
  font-weight: 700;
  letter-spacing: .1em;
  text-transform: uppercase;
}

.value {
  overflow-wrap: anywhere;
  color: var(--text);
}

.notice {
  margin: 0;
  padding: 12px 14px;
  color: #aab7be;
  background: rgba(232, 200, 114, .055);
  border: 1px solid rgba(232, 200, 114, .2);
  border-left: 2px solid var(--warning);
  font-size: 13px;
}

.notice strong { color: var(--warning); font-weight: 600; }

.section-heading {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 20px;
  margin-bottom: 18px;
}

.section-heading h2 {
  margin: 0;
  color: #edf4f7;
  font-size: 18px;
  font-weight: 500;
}

.target-count { color: var(--muted); font-size: 12px; }

.targets {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
}

.target-card {
  --status-color: var(--muted);
  min-width: 0;
  overflow: hidden;
  background: var(--surface);
  border: 1px solid var(--border);
  border-top: 2px solid var(--status-color);
}

.status-verified { --status-color: var(--accent); }
.status-failed { --status-color: var(--danger); }
.status-pending { --status-color: var(--warning); }

.target-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 20px;
  padding: 20px 22px 18px;
  background: var(--surface-raised);
  border-bottom: 1px solid var(--border);
}

.target-id {
  display: block;
  margin-bottom: 4px;
  color: var(--muted);
  font-size: 11px;
}

.target-header h3 {
  margin: 0;
  color: #f0f6f8;
  font-size: 19px;
  font-weight: 550;
  line-height: 1.25;
}

.status-badge {
  flex: 0 0 auto;
  display: inline-flex;
  align-items: center;
  gap: 7px;
  padding: 5px 8px;
  color: var(--status-color);
  background: color-mix(in srgb, var(--status-color) 9%, transparent);
  border: 1px solid color-mix(in srgb, var(--status-color) 28%, transparent);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: .08em;
}

.status-dot {
  width: 6px;
  height: 6px;
  background: currentColor;
  border-radius: 50%;
  box-shadow: 0 0 9px currentColor;
}

.target-details {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 20px 24px;
  margin: 0;
  padding: 22px;
}

.detail { min-width: 0; }
.detail--wide { grid-column: 1 / -1; }

dd {
  min-width: 0;
  margin: 0;
  overflow-wrap: anywhere;
  color: #cbd6db;
}

code { color: #cbd6db; font: inherit; }

.transport-warning {
  padding: 10px 12px;
  background: rgba(232, 200, 114, .06);
  border: 1px solid rgba(232, 200, 114, .18);
}

.transport-warning dt,
.transport-warning dd,
.transport-warning code { color: var(--warning); }

.actions {
  display: flex;
  gap: 6px;
  padding: 14px 16px;
  background: #0c1217;
  border-top: 1px solid var(--border);
}

.actions a {
  padding: 7px 9px;
  color: var(--accent);
  text-decoration: none;
  border: 1px solid transparent;
  font-size: 12px;
}

.actions a:hover {
  background: var(--accent-soft);
  border-color: rgba(99, 220, 255, .22);
}

@media (max-width: 760px) {
  .shell { padding: 42px 18px 56px; }
  .intro { margin-bottom: 34px; }
  .node-meta,
  .targets { grid-template-columns: 1fr; }
  .meta-item--wide { grid-column: auto; }
}

@media (max-width: 420px) {
  .target-header { display: block; }
  .status-badge { margin-top: 14px; }
  .target-details { grid-template-columns: 1fr; }
  .detail--wide { grid-column: auto; }
  .actions { flex-wrap: wrap; }
}
</style>
</head>
<body>
<main class="shell">
<header class="intro">
<p class="eyebrow">Continuity monitor / V0</p>
<h1>Canary status</h1>
<div class="node-meta">
<div class="meta-item"><div class="label">Node</div><div class="value">"#;

/// Render the public multi-target status page from an immutable snapshot.
pub fn render_status_page(snapshot: &RuntimeSnapshot) -> String {
    let mut page = String::from(PAGE_HEAD);
    push_escaped(&mut page, &snapshot.node_id);
    page.push_str("</div></div><div class=\"meta-item\"><div class=\"label\">Snapshot</div><div class=\"value\">");
    push_escaped(&mut page, &snapshot.generated_at.to_rfc3339());
    page.push_str("</div></div><div class=\"meta-item meta-item--wide\"><div class=\"label\">Config digest</div><div class=\"value\">");
    push_escaped(&mut page, &snapshot.config_digest);
    page.push_str("</div></div></div><p class=\"notice\" role=\"note\"><strong>Public evidence:</strong> Raw Nitro evidence can expose infrastructure metadata and is public in V0.</p></header><section aria-labelledby=\"targets-heading\"><div class=\"section-heading\"><h2 id=\"targets-heading\">Targets</h2><span class=\"target-count\">");
    page.push_str(&snapshot.targets.len().to_string());
    page.push_str(if snapshot.targets.len() == 1 {
        " target monitored"
    } else {
        " targets monitored"
    });
    page.push_str("</span></div><div class=\"targets\">");

    for target in &snapshot.targets {
        page.push_str("<article class=\"target-card ");
        page.push_str(status_class(target.status));
        page.push_str("\"><header class=\"target-header\"><div><span class=\"target-id\">");
        push_escaped(&mut page, &target.id);
        page.push_str("</span><h3>");
        push_escaped(&mut page, &target.name);
        page.push_str("</h3></div><span class=\"status-badge\"><span class=\"status-dot\" aria-hidden=\"true\"></span>");
        push_escaped(&mut page, status_text(target.status));
        page.push_str("</span></header><dl class=\"target-details\"><div class=\"detail detail--wide\"><dt>Target</dt><dd><code>");
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
            "</dl><nav class=\"actions\" aria-label=\"Target artifacts\"><a href=\"/targets/",
        );
        push_escaped(&mut page, &target.id);
        page.push_str("/statement\">Statement</a><a href=\"/targets/");
        push_escaped(&mut page, &target.id);
        page.push_str("/evidence\">Evidence</a><a href=\"/targets/");
        push_escaped(&mut page, &target.id);
        page.push_str("/history\">History</a></nav></article>");
    }

    page.push_str("</div></section></main></body></html>");
    page
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
            '\"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#x27;"),
            _ => output.push(character),
        }
    }
}
