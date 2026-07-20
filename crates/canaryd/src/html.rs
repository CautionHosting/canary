//! Deliberately small, server-rendered public status page.
//!
//! The page has no client-side code. Every string interpolated into it is
//! escaped so target configuration cannot become executable HTML.

use crate::model::RuntimeSnapshot;

/// Render the public multi-target status page from an immutable snapshot.
pub fn render_status_page(snapshot: &RuntimeSnapshot) -> String {
    let mut page = String::from(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Canary status</title></head><body><main><h1>Canary status</h1>",
    );
    page.push_str("<p>Node: ");
    push_escaped(&mut page, &snapshot.node_id);
    page.push_str("</p><p>Config digest: ");
    push_escaped(&mut page, &snapshot.config_digest);
    page.push_str("</p><p><strong>Warning:</strong> Raw Nitro evidence can expose infrastructure metadata and is public in V0.</p><ul>");

    for target in &snapshot.targets {
        page.push_str("<li><h2>");
        push_escaped(&mut page, &target.name);
        page.push_str("</h2><dl><dt>ID</dt><dd>");
        push_escaped(&mut page, &target.id);
        page.push_str("</dd><dt>Target</dt><dd>");
        push_escaped(&mut page, &target.target_origin);
        page.push_str("</dd><dt>Status</dt><dd>");
        push_escaped(&mut page, status_text(target.status));
        page.push_str("</dd><dt>Reason</dt><dd>");
        push_escaped(&mut page, &target.reason);
        page.push_str("</dd><dt>Expires</dt><dd>");
        push_escaped(&mut page, &target.expires_at.to_rfc3339());
        page.push_str("</dd>");
        if let Some(warning) = &target.transport_warning {
            page.push_str("<dt>Transport warning</dt><dd>");
            push_escaped(&mut page, warning);
            page.push_str("</dd>");
        }
        page.push_str("</dl><p><a href=\"/targets/");
        push_escaped(&mut page, &target.id);
        page.push_str("/statement\">Statement</a> · <a href=\"/targets/");
        push_escaped(&mut page, &target.id);
        page.push_str("/evidence\">Evidence</a> · <a href=\"/targets/");
        push_escaped(&mut page, &target.id);
        page.push_str("/history\">History</a></p></li>");
    }

    page.push_str("</ul></main></body></html>");
    page
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
