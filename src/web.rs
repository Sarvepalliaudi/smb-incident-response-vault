// smb-ir-vault — Small Business 6-Phase Incident Response Plan & SHA3-512 Forensic Evidence Locker
// Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan.
// B.Tech Computer Science and Engineering (Cybersecurity), Final Year (7th Semester),
// Dhanalakshmi Srinivasan University, Tiruchirappalli, Tamil Nadu, India.
// Cybersecurity Virtual Internship — Dev/Craft by Fennark: https://devcraft.fennark.xyz
// Intern ID DEV-CRAFT-BQ2VPH, Task 7: Incident Response Plan.
// LinkedIn: https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/
// GitHub: https://github.com/Sarvepalliaudi
// This specification and dual hardware-software architecture is original work created solely for this application.

use crate::locker::{self, OperatorProfile, PROPRIETARY_NOTICE, TOOL_NAME};
use axum::extract::{ConnectInfo, Form, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const REQUEST_LIMIT: usize = 5;
const WINDOW: Duration = Duration::from_secs(60);

#[derive(Clone)]
struct AppState {
    requests: Arc<Mutex<HashMap<IpAddr, VecDeque<Instant>>>>,
}

#[derive(Deserialize)]
struct ArtifactForm {
    responder_name: String,
    organization: String,
    text: String,
}

#[derive(Deserialize)]
struct VerifyForm {
    responder_name: String,
    organization: String,
    text: String,
    expected_sha3_512: String,
}

#[derive(Deserialize)]
struct AttributionForm {
    responder_name: String,
    organization: String,
}

pub async fn serve() -> Result<(), Box<dyn std::error::Error>> {
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_owned())
        .parse::<u16>()?;
    let address = SocketAddr::from(([0, 0, 0, 0], port));
    let app = Router::new()
        .route("/", get(index))
        .route("/hash", post(hash_text))
        .route("/verify", post(verify_text))
        .route("/verify-sample", post(verify_sample))
        .with_state(AppState {
            requests: Arc::new(Mutex::new(HashMap::new())),
        });
    let listener = tokio::net::TcpListener::bind(address).await?;
    println!("Serving {TOOL_NAME} at http://{address}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn index() -> Html<String> {
    Html(format!(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>smb-ir-vault | Small Business IRP & Evidence Vault</title>\
         <style>body{{max-width:920px;margin:2rem auto;padding:0 1rem;font:16px/1.55 ui-monospace,monospace;color:#111;background:#fff}}\
         header,section{{border:1px solid #333;padding:1rem;margin:1rem 0}}\
         h1,h2{{line-height:1.2}}label{{display:block;margin:.7rem 0 .2rem}}\
         input,textarea,button{{font:inherit;padding:.45rem;max-width:100%}}\
         textarea{{width:98%;min-height:8rem}}button{{background:#111;color:#fff;cursor:pointer}}\
         code,pre{{overflow-wrap:anywhere;white-space:pre-wrap}}.credit{{font-size:.9rem}}</style>\
         <header><h1>{}</h1><p>Software Architect &amp; Creator: {}<br>\
         University: {}<br>Internship: {}<br>\
         <a href=\"{}\">LinkedIn</a> | <a href=\"{}\">GitHub</a></p>\
         <p>{}</p><p>Defensive-use evidence hashing only. SHA3-512 provides integrity checking, \
         not a signature or chain-of-custody proof. No JavaScript; evidence inputs are not persisted.</p></header>\
         <main><section><h2>Six-phase response checklist</h2><ol>\
         <li><label><input type=\"checkbox\"> Preparation — verify encrypted 3-2-1 backups, MFA, monitoring, and authority.</label></li>\
         <li><label><input type=\"checkbox\"> Detection &amp; Analysis — record timestamps, preserve indicators, classify severity.</label></li>\
         <li><label><input type=\"checkbox\"> Containment — isolate safely, revoke tokens, block confirmed C2, segment clean systems.</label></li>\
         <li><label><input type=\"checkbox\"> Eradication — remove persistence, patch entry points, reset credentials.</label></li>\
         <li><label><input type=\"checkbox\"> Recovery — rebuild, restore verified backups, monitor 72 hours, obtain sign-off.</label></li>\
         <li><label><input type=\"checkbox\"> Lessons Learned — complete blameless review and track actions within five business days.</label></li>\
         </ol><p>Operational detail: <a href=\"https://github.com/Sarvepalliaudi/devcraft-pqc-hardware-security-suite\">SMB incident-response playbook repository</a> (deploy the playbooks with this service).</p></section>\
         <section><h2>Hash a text artifact</h2><form method=\"post\" action=\"/hash\">\
         <label>Responder / Operator Name (required)<input name=\"responder_name\" required></label>\
         <label>Organization (required)<input name=\"organization\" required></label>\
         <label>Artifact text<textarea name=\"text\" required></textarea></label>\
         <button type=\"submit\">Compute SHA3-512</button></form></section>\
         <section><h2>Verify supplied text</h2><form method=\"post\" action=\"/verify\">\
         <label>Responder / Operator Name (required)<input name=\"responder_name\" required></label>\
         <label>Organization (required)<input name=\"organization\" required></label>\
         <label>Artifact text<textarea name=\"text\" required></textarea></label>\
         <label>Expected SHA3-512 digest<input name=\"expected_sha3_512\" minlength=\"128\" maxlength=\"128\" required></label>\
         <button type=\"submit\">Verify text</button></form></section>\
         <section><h2>Built-in synthetic evidence check</h2><p>Verifies the bundled INC-2026-042 sample manifest when available.</p>\
         <form method=\"post\" action=\"/verify-sample\">\
         <label>Responder / Operator Name (required)<input name=\"responder_name\" required></label>\
         <label>Organization (required)<input name=\"organization\" required></label>\
         <button type=\"submit\">Verify bundled sample</button></form></section></main>\
         <footer class=\"credit\"><p>{}</p><p>University: {}<br>Internship: {}<br>\
         LinkedIn: {}<br>GitHub: {}</p></footer></html>",
        TOOL_NAME,
        locker::CREATOR,
        locker::UNIVERSITY,
        format!(
            "{} ({})",
            locker::INTERNSHIP,
            "https://devcraft.fennark.xyz"
        ),
        locker::LINKEDIN,
        locker::GITHUB,
        PROPRIETARY_NOTICE,
        PROPRIETARY_NOTICE,
        locker::UNIVERSITY,
        locker::INTERNSHIP,
        locker::LINKEDIN,
        locker::GITHUB,
    ))
}

async fn hash_text(
    State(state): State<AppState>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    Form(form): Form<ArtifactForm>,
) -> impl IntoResponse {
    if let Err(response) = admit_request(&state, address.ip()) {
        return response;
    }
    if let Err(message) = validate_attribution(&form.responder_name, &form.organization) {
        return error_page(StatusCode::BAD_REQUEST, message);
    }
    let digest = locker::sha3_512_hex(form.text.as_bytes());
    Html(format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Hash result</title>\
         <h1>SHA3-512 result</h1><p>Responder: {}</p><p>Organization: {}</p>\
         <pre>{}</pre><p><a href=\"/\">Return</a></p>",
        escape_html(form.responder_name.trim()),
        escape_html(form.organization.trim()),
        digest
    ))
    .into_response()
}

async fn verify_text(
    State(state): State<AppState>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    Form(form): Form<VerifyForm>,
) -> impl IntoResponse {
    if let Err(response) = admit_request(&state, address.ip()) {
        return response;
    }
    if let Err(message) = validate_attribution(&form.responder_name, &form.organization) {
        return error_page(StatusCode::BAD_REQUEST, message);
    }
    if form.expected_sha3_512.len() != 128
        || !form
            .expected_sha3_512
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Expected digest must be exactly 128 hexadecimal characters.",
        );
    }
    let actual = locker::sha3_512_hex(form.text.as_bytes());
    let intact = actual.eq_ignore_ascii_case(&form.expected_sha3_512);
    let status = if intact {
        "[OK] INTACT"
    } else {
        "[ALERT] TAMPERED"
    };
    Html(format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Verification result</title>\
         <h1>{status}</h1><p>Responder: {}</p><p>Organization: {}</p>\
         <p>Computed SHA3-512: <code>{actual}</code></p><p><a href=\"/\">Return</a></p>",
        escape_html(form.responder_name.trim()),
        escape_html(form.organization.trim()),
    ))
    .into_response()
}

async fn verify_sample(
    State(state): State<AppState>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    Form(form): Form<AttributionForm>,
) -> impl IntoResponse {
    if let Err(response) = admit_request(&state, address.ip()) {
        return response;
    }
    if let Err(message) = validate_attribution(&form.responder_name, &form.organization) {
        return error_page(StatusCode::BAD_REQUEST, message);
    }
    let manifest_path = std::path::Path::new("sample_evidence/EVIDENCE_MANIFEST.json");
    let results = match locker::verify_manifest(manifest_path) {
        Ok(results) => results,
        Err(error) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Could not verify bundled manifest: {error}"),
            )
        }
    };
    let all_intact = !results.is_empty() && results.iter().all(locker::VerificationResult::intact);
    let status = if all_intact {
        "[OK] INTACT"
    } else {
        "[ALERT] TAMPERED / MISSING"
    };
    let details = results
        .iter()
        .map(|result| {
            let state = if result.intact() {
                "INTACT"
            } else {
                "TAMPERED / MISSING"
            };
            format!(
                "<li>{}: {} — <code>{}</code></li>",
                escape_html(&result.path),
                state,
                result.actual.as_deref().unwrap_or("missing")
            )
        })
        .collect::<String>();
    Html(format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Sample verification</title>\
         <h1>{status}</h1><p>Responder: {}</p><p>Organization: {}</p><ul>{details}</ul>\
         <p><a href=\"/\">Return</a></p>",
        escape_html(form.responder_name.trim()),
        escape_html(form.organization.trim()),
    ))
    .into_response()
}

fn admit_request(state: &AppState, ip: IpAddr) -> Result<(), axum::response::Response> {
    let mut buckets = state.requests.lock().map_err(|_| {
        error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Rate limiter is unavailable; request was not processed.",
        )
    })?;
    let now = Instant::now();
    buckets.retain(|_, bucket| {
        while bucket
            .front()
            .map(|time| now.duration_since(*time) >= WINDOW)
            .unwrap_or(false)
        {
            bucket.pop_front();
        }
        !bucket.is_empty()
    });
    let bucket = buckets.entry(ip).or_default();
    if bucket.len() >= REQUEST_LIMIT {
        return Err(error_page(
            StatusCode::TOO_MANY_REQUESTS,
            "Request limit reached: at most 5 evidence operations per IP per minute.",
        ));
    }
    bucket.push_back(now);
    Ok(())
}

fn validate_attribution(name: &str, organization: &str) -> Result<OperatorProfile, &'static str> {
    if name.trim().is_empty() || organization.trim().is_empty() {
        return Err("Responder / Operator Name and Organization are required.");
    }
    Ok(OperatorProfile {
        responder_name: name.trim().to_owned(),
        organization: organization.trim().to_owned(),
    })
}

fn error_page(status: StatusCode, message: impl AsRef<str>) -> axum::response::Response {
    (
        status,
        Html(format!(
            "<!doctype html><meta charset=\"utf-8\"><title>Request error</title>\
             <h1>Request not completed</h1><p>{}</p><p><a href=\"/\">Return</a></p>",
            escape_html(message.as_ref())
        )),
    )
        .into_response()
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escapes_untrusted_text() {
        assert_eq!(
            escape_html("<script>&\"'"),
            "&lt;script&gt;&amp;&quot;&#39;"
        );
    }

    #[test]
    fn operator_attribution_is_required_and_trimmed() {
        assert!(validate_attribution(" ", "Business").is_err());
        let profile = validate_attribution(" Ada ", " Shop ").expect("valid attribution");
        assert_eq!(profile.responder_name, "Ada");
        assert_eq!(profile.organization, "Shop");
    }

    #[test]
    fn limiter_allows_five_operations_and_rejects_the_sixth() {
        let state = AppState {
            requests: Arc::new(Mutex::new(HashMap::new())),
        };
        let ip = "192.0.2.10".parse().expect("valid test IP");
        for _ in 0..REQUEST_LIMIT {
            assert!(admit_request(&state, ip).is_ok());
        }
        let response = admit_request(&state, ip).expect_err("sixth request must be limited");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
