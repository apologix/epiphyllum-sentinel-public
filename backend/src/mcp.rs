//! Read-only MCP resources. The model never receives a client or executable tools.
//! Protocol 2026-07-28; immutable synthetic snapshots, not a universal live log cursor.
use crate::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::StreamExt;
use serde_json::{Value, json};
use sqlx::Row;
use std::{collections::HashSet, net::SocketAddr, time::Duration};
use uuid::Uuid;

pub const PROTOCOL_VERSION: &str = "2026-07-28";
const MAX_HTTP_BYTES: usize = 4 * 1024 * 1024;
const MAX_TEXT_BYTES: usize = 1024 * 1024;
const FIXTURE_ENDPOINT: &str = "http://mcp-fixture:8090/mcp";

pub fn lab_resource(uri: &str) -> Option<(&'static str, &'static [&'static str])> {
    match uri {
        "logs://nginx/access" | "logs://nginx/error" => Some(("nginx", &["f5:nginx"])),
        "logs://mysql/error" | "logs://mysql/audit" => {
            Some(("mysql", &["oracle:mysql", "mariadb:mariadb"]))
        }
        "logs://node/app" | "logs://node/security" => Some(("node", &["nodejs:node.js"])),
        "logs://ssh/auth" => Some(("ssh", &["openbsd:openssh"])),
        _ => None,
    }
}

pub fn lab_metadata(page: &Value, uri: &str) -> anyhow::Result<(String, Option<String>)> {
    let (service, products) =
        lab_resource(uri).ok_or_else(|| anyhow::anyhow!("mcp_lab_resource_denied"))?;
    let metadata = &page["service"];
    anyhow::ensure!(
        metadata.as_object().is_some_and(|object| object.len() == 5
            && ["id", "product", "version", "version_source", "routes"]
                .iter()
                .all(|key| object.contains_key(*key))),
        "mcp_lab_metadata_invalid"
    );
    let product = metadata["product"]
        .as_str()
        .filter(|product| products.contains(product))
        .ok_or_else(|| anyhow::anyhow!("mcp_lab_metadata_invalid"))?;
    anyhow::ensure!(metadata["id"] == service, "mcp_lab_metadata_invalid");
    let routes = metadata["routes"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("mcp_lab_metadata_invalid"))?;
    anyhow::ensure!(
        routes.len() <= 12
            && routes
                .iter()
                .all(|route| route.as_str().is_some_and(|path| {
                    !path.is_empty()
                        && path.len() <= 80
                        && path.starts_with('/')
                        && path
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"/_-".contains(&c))
                })),
        "mcp_lab_metadata_invalid"
    );
    match metadata["version"].as_str() {
        Some(version) => {
            anyhow::ensure!(
                metadata["version_source"] == "service_status"
                    && !version.is_empty()
                    && version.len() <= 64
                    && version
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"._+-".contains(&c)),
                "mcp_lab_metadata_invalid"
            );
            Ok((product.to_owned(), Some(version.to_owned())))
        }
        None => {
            anyhow::ensure!(
                metadata["version"].is_null() && metadata["version_source"] == "unavailable",
                "mcp_lab_metadata_invalid"
            );
            Ok((product.to_owned(), None))
        }
    }
}

pub const BUNDLED_CA_PEM: &[u8] = include_bytes!("../../lab/lab-ca.pem");

pub fn package_ca_pem() -> Vec<u8> {
    std::env::var("MCP_LAB_CA_FILE")
        .ok()
        .and_then(|p| std::fs::read(p).ok())
        .filter(|b| !b.is_empty())
        .unwrap_or_else(|| BUNDLED_CA_PEM.to_vec())
}

pub const DEFAULT_LAB_NETWORK: &str = "192.168.122.0/24";

fn parse_ipv4_cidr(cidr: &str) -> Option<(std::net::Ipv4Addr, u32)> {
    let (ip_str, prefix_str) = match cidr.split_once('/') {
        Some((ip, prefix)) => (ip.trim(), prefix.trim()),
        None => (cidr.trim(), "32"),
    };
    let ip: std::net::Ipv4Addr = ip_str.parse().ok()?;
    let prefix: u32 = prefix_str.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let mask = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    Some((ip, mask))
}

pub fn is_in_lab_network(ip: std::net::Ipv4Addr) -> bool {
    let configured = std::env::var("MCP_LAB_NETWORK")
        .or_else(|_| std::env::var("MCP_LAB_SUBNET"))
        .or_else(|_| std::env::var("MCP_LAB_ALLOWED_CIDR"))
        .unwrap_or_else(|_| DEFAULT_LAB_NETWORK.to_owned());
    for raw in configured.split(',') {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        let matches = parse_ipv4_cidr(entry)
            .is_some_and(|(net_ip, mask)| (u32::from(ip) & mask) == (u32::from(net_ip) & mask));
        if matches {
            return true;
        }
    }
    false
}

/// Forma obligatoria de un endpoint de laboratorio: HTTPS sobre una IPv4
/// privada que pertenezca a la red aislada del laboratorio, puerto 443 y
/// ruta /mcp, sin credenciales, redirecciones ni parámetros.
pub fn lab_endpoint_shape(endpoint: &str) -> anyhow::Result<reqwest::Url> {
    let url = reqwest::Url::parse(endpoint)?;
    let ip: std::net::Ipv4Addr = url.host_str().unwrap_or("").parse()?;
    anyhow::ensure!(
        ip.is_private()
            && is_in_lab_network(ip)
            && url.scheme() == "https"
            && url.port_or_known_default() == Some(443)
            && url.path() == "/mcp"
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "mcp_lab_destination_denied"
    );
    Ok(url)
}

pub fn validate_lab_endpoint(endpoint: &str) -> anyhow::Result<reqwest::Url> {
    lab_endpoint_shape(endpoint)
}

pub fn lab_client(ca_pem: Option<&[u8]>) -> anyhow::Result<reqwest::Client> {
    let bundled = package_ca_pem();
    let pem = ca_pem.filter(|p| !p.is_empty()).unwrap_or(&bundled);
    anyhow::ensure!(pem.len() <= 16384, "mcp_lab_ca_invalid");
    let ca = reqwest::Certificate::from_pem(pem)?;
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca)
        .timeout(Duration::from_secs(10));
    if let Ok(proxy) = std::env::var("MCP_LAB_PROXY")
        .map(|v| v.trim().to_owned())
        .and_then(|v| {
            if v.is_empty() {
                Err(std::env::VarError::NotPresent)
            } else {
                Ok(v)
            }
        })
    {
        let parsed = reqwest::Url::parse(&proxy)?;
        let ip: std::net::Ipv4Addr = parsed.host_str().unwrap_or("").parse()?;
        anyhow::ensure!(
            parsed.scheme() == "http"
                && ip.is_private()
                && parsed.port().is_some()
                && parsed.username().is_empty()
                && parsed.password().is_none()
                && parsed.path() == "/"
                && parsed.query().is_none()
                && parsed.fragment().is_none(),
            "mcp_lab_proxy_invalid"
        );
        builder = builder.proxy(reqwest::Proxy::all(proxy)?);
    } else {
        builder = builder.no_proxy();
    }
    Ok(builder.build()?)
}

/// Configuration may name a resource URI; it is never interpreted as a URL to fetch.
pub fn validate_endpoint(endpoint: &str) -> anyhow::Result<reqwest::Url> {
    let url =
        reqwest::Url::parse(endpoint).map_err(|_| anyhow::anyhow!("mcp_destination_denied"))?;
    anyhow::ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && endpoint.len() <= 2048,
        "mcp_destination_denied"
    );
    if endpoint == FIXTURE_ENDPOINT {
        anyhow::ensure!(
            std::env::var("MCP_ALLOW_SYNTHETIC_FIXTURE").as_deref() == Ok("1"),
            "mcp_fixture_not_enabled"
        );
        return Ok(url);
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("mcp_destination_denied"))?;
    let origin = url.origin().ascii_serialization();
    anyhow::ensure!(
        url.scheme() == "https"
            && url.port_or_known_default() == Some(443)
            && host.parse::<std::net::IpAddr>().is_err()
            && std::env::var("MCP_ALLOWED_ORIGINS")
                .unwrap_or_default()
                .split(',')
                .any(|v| v.trim().trim_end_matches('/') == origin),
        "mcp_destination_denied"
    );
    Ok(url)
}

async fn pinned_client(url: &reqwest::Url) -> anyhow::Result<reqwest::Client> {
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("mcp_destination_denied"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("mcp_destination_denied"))?;
    let addresses: Vec<SocketAddr> = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host((host, port)),
    )
    .await
    .map_err(|_| anyhow::anyhow!("mcp_dns_timeout"))?
    .map_err(|_| anyhow::anyhow!("mcp_dns_failed"))?
    .collect();
    let fixture = url.as_str() == FIXTURE_ENDPOINT;
    anyhow::ensure!(
        !addresses.is_empty()
            && addresses.iter().all(|a| {
                if fixture {
                    matches!(a.ip(), std::net::IpAddr::V4(ip) if ip.is_private())
                } else {
                    provider::public_ip(a.ip())
                }
            }),
        "mcp_dns_destination_denied"
    );
    Ok(reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(host, &addresses)
        .timeout(Duration::from_secs(10))
        .build()?)
}

fn metadata() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": {"name":"epiphyllum-sentinel","version":"0.1.0"},
        "io.modelcontextprotocol/clientCapabilities": {}
    })
}
fn header_name(value: &str) -> String {
    if value.trim() == value
        && value.bytes().all(|b| (0x20..=0x7e).contains(&b))
        && !(value.starts_with("=?base64?") && value.ends_with("?="))
    {
        value.to_owned()
    } else {
        format!("=?base64?{}?=", STANDARD.encode(value))
    }
}
fn rpc_result(value: Value, id: u64) -> anyhow::Result<Option<Value>> {
    anyhow::ensure!(value["jsonrpc"] == "2.0", "mcp_invalid_envelope");
    if let Some(method) = value["method"].as_str() {
        anyhow::ensure!(value.get("id").is_none(), "mcp_server_request_denied");
        anyhow::ensure!(
            matches!(method, "notifications/progress" | "notifications/message"),
            "mcp_notification_unsupported"
        );
        return Ok(None);
    }
    anyhow::ensure!(
        value["id"] == id && value.get("error").is_none(),
        "mcp_rpc_failed"
    );
    let result = value
        .get("result")
        .ok_or_else(|| anyhow::anyhow!("mcp_result_missing"))?;
    anyhow::ensure!(
        result["resultType"] == "complete",
        "mcp_interaction_unsupported"
    );
    Ok(Some(result.clone()))
}
fn frame_result(frame: &[u8], id: u64) -> anyhow::Result<Option<Value>> {
    let frame = std::str::from_utf8(frame).map_err(|_| anyhow::anyhow!("mcp_invalid_utf8"))?;
    let data = frame
        .lines()
        .filter_map(|line| {
            line.strip_prefix("data:")
                .map(|s| s.strip_prefix(' ').unwrap_or(s))
        })
        .collect::<Vec<_>>()
        .join("\n");
    if data.is_empty() {
        return Ok(None);
    }
    rpc_result(
        serde_json::from_str(&data).map_err(|_| anyhow::anyhow!("mcp_invalid_json"))?,
        id,
    )
}
async fn rpc(
    client: &reqwest::Client,
    url: &reqwest::Url,
    credential: Option<&str>,
    method: &str,
    mut params: Value,
    id: u64,
) -> anyhow::Result<Value> {
    anyhow::ensure!(
        matches!(method, "resources/list" | "resources/read"),
        "mcp_method_denied"
    );
    params["_meta"] = metadata();
    let mut request = client
        .post(url.clone())
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", PROTOCOL_VERSION)
        .header("Mcp-Method", method);
    if let Some(uri) = params["uri"].as_str() {
        request = request.header("Mcp-Name", header_name(uri));
    }
    if let Some(secret) = credential {
        anyhow::ensure!(
            secret.len() <= 8192 && !secret.contains(['\r', '\n']),
            "mcp_credential_invalid"
        );
        request = request.bearer_auth(secret);
    }
    let response = request
        .json(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("mcp_connection_failed"))?;
    anyhow::ensure!(response.status().is_success(), "mcp_http_failed");
    anyhow::ensure!(
        response
            .content_length()
            .is_none_or(|n| n <= MAX_HTTP_BYTES as u64),
        "mcp_response_too_large"
    );
    let mime = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    let sse = mime == "text/event-stream";
    anyhow::ensure!(sse || mime == "application/json", "mcp_content_type_denied");
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    let mut total = 0;
    let mut notifications = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| anyhow::anyhow!("mcp_response_failed"))?;
        total += chunk.len();
        anyhow::ensure!(total <= MAX_HTTP_BYTES, "mcp_response_too_large");
        bytes.extend_from_slice(&chunk);
        if sse {
            loop {
                let ending = bytes
                    .windows(2)
                    .position(|w| w == b"\n\n")
                    .map(|n| (n, 2))
                    .or_else(|| {
                        bytes
                            .windows(4)
                            .position(|w| w == b"\r\n\r\n")
                            .map(|n| (n, 4))
                    });
                let Some((end, length)) = ending else {
                    break;
                };
                if let Some(result) = frame_result(&bytes[..end], id)? {
                    return Ok(result);
                }
                notifications += 1;
                anyhow::ensure!(notifications <= 64, "mcp_notifications_exceeded");
                bytes.drain(..end + length);
            }
        }
    }
    anyhow::ensure!(!sse, "mcp_response_incomplete");
    rpc_result(
        serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("mcp_invalid_json"))?,
        id,
    )?
    .ok_or_else(|| anyhow::anyhow!("mcp_response_incomplete"))
}

async fn read_with_client(
    client: &reqwest::Client,
    url: &reqwest::Url,
    resource_uri: &str,
    credential: Option<&str>,
) -> anyhow::Result<String> {
    anyhow::ensure!(
        !resource_uri.is_empty()
            && resource_uri.len() <= 2048
            && !resource_uri.chars().any(char::is_control),
        "mcp_resource_invalid"
    );
    let mut cursor: Option<String> = None;
    let mut seen = HashSet::new();
    let mut listed = false;
    for page in 0..16 {
        let params = cursor
            .as_ref()
            .map_or_else(|| json!({}), |c| json!({"cursor":c}));
        let result = rpc(client, url, credential, "resources/list", params, page + 1).await?;
        let resources = result["resources"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("mcp_resources_invalid"))?;
        anyhow::ensure!(resources.len() <= 100, "mcp_resource_page_exceeded");
        listed |= resources
            .iter()
            .any(|r| r["uri"].as_str() == Some(resource_uri));
        if listed {
            break;
        }
        match result.get("nextCursor") {
            None | Some(Value::Null) => break,
            Some(Value::String(next)) if !next.is_empty() && next.len() <= 2048 => {
                anyhow::ensure!(seen.insert(next.clone()), "mcp_cursor_repeated");
                cursor = Some(next.clone());
            }
            _ => anyhow::bail!("mcp_cursor_invalid"),
        }
    }
    anyhow::ensure!(listed, "mcp_resource_not_listed");
    let result = rpc(
        client,
        url,
        credential,
        "resources/read",
        json!({"uri":resource_uri}),
        100,
    )
    .await?;
    let contents = result["contents"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("mcp_contents_invalid"))?;
    anyhow::ensure!(contents.len() == 1, "mcp_single_resource_required");
    let content = &contents[0];
    anyhow::ensure!(
        content["uri"] == resource_uri && content.get("blob").is_none(),
        "mcp_resource_mismatch"
    );
    let mime = content["mimeType"].as_str().unwrap_or("text/plain");
    anyhow::ensure!(
        matches!(
            mime,
            "text/plain" | "application/x-ndjson" | "application/json"
        ),
        "mcp_resource_type_denied"
    );
    let text = content["text"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("mcp_text_required"))?;
    anyhow::ensure!(text.len() <= MAX_TEXT_BYTES, "mcp_text_too_large");
    anyhow::ensure!(
        text.split_inclusive('\n').count() <= 2000,
        "mcp_record_count_exceeded"
    );
    Ok(text.to_owned())
}

pub async fn read_resource(
    endpoint: &str,
    resource_uri: &str,
    credential: Option<&str>,
) -> anyhow::Result<String> {
    let url = validate_endpoint(endpoint)?;
    let client = pinned_client(&url).await?;
    read_with_client(&client, &url, resource_uri, credential).await
}

async fn list_lab_resources(
    client: &reqwest::Client,
    url: &reqwest::Url,
    credential: &str,
) -> anyhow::Result<HashSet<String>> {
    let listed = rpc(
        client,
        url,
        Some(credential),
        "resources/list",
        json!({}),
        1,
    )
    .await?;
    let resources = listed["resources"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("mcp_resources_invalid"))?;
    Ok(resources
        .iter()
        .filter_map(|item| item["uri"].as_str())
        .filter(|uri| lab_resource(uri).is_some())
        .map(str::to_owned)
        .collect())
}

pub async fn probe_lab_connection(
    endpoint: &str,
    credential: &str,
    ca_pem: Option<&str>,
) -> anyhow::Result<HashSet<String>> {
    let url = lab_endpoint_shape(endpoint)?;
    let client = lab_client(ca_pem.map(|s| s.as_bytes()))?;
    list_lab_resources(&client, &url, credential).await
}

pub async fn check_lab_resource(
    endpoint: &str,
    uri: &str,
    credential: &str,
    ca_pem: Option<&str>,
) -> anyhow::Result<String> {
    let url = lab_endpoint_shape(endpoint)?;
    anyhow::ensure!(lab_resource(uri).is_some(), "mcp_lab_resource_denied");
    let client = lab_client(ca_pem.map(|s| s.as_bytes()))?;
    anyhow::ensure!(
        list_lab_resources(&client, &url, credential)
            .await?
            .contains(uri),
        "mcp_resource_not_listed"
    );
    let result = rpc(
        &client,
        &url,
        Some(credential),
        "resources/read",
        json!({"uri":uri}),
        2,
    )
    .await?;
    let contents = result["contents"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("mcp_contents_invalid"))?;
    anyhow::ensure!(
        contents.len() == 1
            && contents[0]["uri"] == uri
            && contents[0]["mimeType"] == "application/json"
            && contents[0].get("blob").is_none(),
        "mcp_resource_mismatch"
    );
    let text = contents[0]["text"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("mcp_text_required"))?;
    anyhow::ensure!(
        text.len() <= MAX_TEXT_BYTES && text.lines().count() <= 2000,
        "mcp_text_too_large"
    );
    let page: Value = serde_json::from_str(text)?;
    lab_metadata(&page, uri)?;
    anyhow::ensure!(
        page["schema_version"] == 1
            && page["source"] == uri.rsplit('/').next().unwrap_or("")
            && page["requested_cursor"].is_null()
            && matches!(
                page["continuity"].as_str(),
                Some("initial" | "continuous" | "rotation")
            )
            && page["records"].is_array()
            && page["next_cursor"].is_string(),
        "mcp_lab_page_invalid"
    );
    Ok(text.to_owned())
}

/// Qué hace el backend con un registro de una página de laboratorio
/// (planning/MCP-EVENT-CONTRACT.md §2.1 y decisión de coexistencia de Allan):
/// los mecanismos son mutuamente excluyentes por registro.
#[derive(Debug)]
pub enum RecordPlan {
    /// El registro trae `derived_events` (válidos o no): manda el adaptador.
    /// Aunque ningún evento supere la validación, NO corre el parser legacy
    /// sobre el mismo hecho: el adaptador ya reclamó la interpretación de
    /// esa línea y un segundo parseo podría duplicar su semántica.
    Derived(contracts::DerivedValidation),
    /// Sin `derived_events` en `logs://nginx/access`: parser actual del
    /// backend (`log_formats::parse`), conservado como fallback.
    LegacyFallback,
    /// Sin `derived_events` en cualquier otro recurso: solo texto, como hoy.
    TextOnly,
}

/// Plan puro por registro: no toca la base y es el punto que ejercitan las
/// pruebas de exclusión mutua e idempotencia sin Postgres.
pub fn plan_record(
    uri: &str,
    record: &Value,
    source_product: &str,
    source_version: Option<&str>,
) -> anyhow::Result<RecordPlan> {
    let Some(raw) = record.get("derived_events") else {
        return Ok(if uri == "logs://nginx/access" {
            RecordPlan::LegacyFallback
        } else {
            RecordPlan::TextOnly
        });
    };
    let (service, products) =
        lab_resource(uri).ok_or_else(|| anyhow::anyhow!("mcp_lab_resource_invalid"))?;
    anyhow::ensure!(
        products.contains(&source_product),
        "mcp_lab_resource_invalid"
    );
    let validation =
        contracts::validate_derived_events(raw, service, source_product, source_version)
            .map_err(|_| anyhow::anyhow!("mcp_lab_derived_invalid"))?;
    Ok(RecordPlan::Derived(validation))
}

/// Fila lista para insertar en `events` a partir de un evento derivado ya
/// validado. El backend fija identidad, alias seudonimizado y mensaje
/// (resumen redactado construido aquí, nunca texto del adaptador).
#[derive(Debug, PartialEq)]
pub struct DerivedRow {
    pub id: Uuid,
    pub event_time: chrono::DateTime<chrono::Utc>,
    pub source: String,
    pub event_type: String,
    pub level: String,
    pub src_ip: Option<String>,
    pub user_alias: Option<String>,
    pub message: String,
    pub parser: String,
    pub http: Option<Value>,
    pub attributes: Option<Value>,
}

pub fn derived_row(
    record_id: Uuid,
    event: &contracts::DerivedEvent,
    session_id: &str,
    ingested_at: chrono::DateTime<chrono::Utc>,
) -> DerivedRow {
    let id = contracts::derived_event_id(
        &record_id,
        &event.parser_name,
        &event.parser_version,
        event.index,
    );
    let user_alias = event
        .username
        .as_ref()
        .map(|u| format!("usuario-{}", &hash(u)[..16]));
    let mut attributes = event.attributes.clone();
    if let Some(slot) = attributes.as_mut().and_then(|a| a.get_mut("db_user")) {
        if let Some(raw) = slot.as_str().map(str::to_owned) {
            *slot = json!(format!("usuario-{}", &hash(&raw)[..16]));
        }
    }
    let summary = if let Some(http) = &event.http {
        let method = http["method"].as_str().unwrap_or("");
        let path = http["normalized_path"]
            .as_str()
            .or_else(|| http["raw_target"].as_str())
            .unwrap_or("");
        let path: String = path.chars().take(128).collect();
        format!(
            "{method} {path} · HTTP {}",
            http["status"].as_u64().unwrap_or(0)
        )
    } else {
        let mut parts = vec![event.event_type.clone()];
        if let Some(alias) = &user_alias {
            parts.push(alias.clone());
        }
        if let Some(ip) = &event.src_ip {
            parts.push(ip.clone());
        }
        parts.join(" · ")
    };
    DerivedRow {
        id,
        event_time: event.timestamp.unwrap_or(ingested_at),
        source: event.source.clone(),
        event_type: event.event_type.clone(),
        level: event.level.clone(),
        src_ip: event.src_ip.clone(),
        user_alias,
        message: contracts::redact(&summary, session_id)
            .chars()
            .take(2048)
            .collect(),
        parser: format!("{}@{}", event.parser_name, event.parser_version),
        http: event.http.clone(),
        attributes,
    }
}

/// Fetch outside transactions; source/config/service are locked and rechecked before capture.
pub async fn poll(app: &App) -> anyhow::Result<()> {
    let sources = sqlx::query("SELECT s.id,s.service_id,s.version,s.capture_version,s.config,c.ciphertext,c.nonce FROM sources s JOIN services v ON v.id=s.service_id LEFT JOIN source_credentials c ON c.source_id=s.id WHERE s.kind='mcp' AND s.enabled AND s.deleted_at IS NULL AND v.enabled AND v.deleted_at IS NULL AND s.updated_at < now()-make_interval(secs => CASE WHEN s.config->>'mode'='incremental_lab' THEN greatest(5,least(300,coalesce((s.config->>'poll_seconds')::int,5))) ELSE 5 END) ORDER BY s.updated_at,s.id LIMIT 16").fetch_all(&app.pool).await?;
    for source in sources {
        let id: Uuid = source.get("id");
        let version: i32 = source.get("version");
        let result = capture(app, &source).await;
        let error = result.err().map(|e| safe_error(&e));
        sqlx::query("UPDATE sources SET status=$3,last_error_code=$4,updated_at=now() WHERE id=$1 AND version=$2")
            .bind(id).bind(version).bind(if error.is_some(){"degraded"}else{"healthy"}).bind(error)
            .execute(&app.pool).await?;
    }
    Ok(())
}
fn safe_error(error: &anyhow::Error) -> &'static str {
    const SAFE: &[&str] = &[
        "mcp_resource_changed",
        "mcp_destination_denied",
        "mcp_fixture_not_enabled",
        "mcp_record_storage_backpressure",
        "mcp_source_changed",
        "mcp_response_too_large",
        "mcp_text_too_large",
        "mcp_record_count_exceeded",
        "mcp_resource_type_denied",
        "mcp_resource_not_listed",
        "mcp_cursor_repeated",
        "mcp_interaction_unsupported",
        "mcp_single_resource_required",
        "mcp_connection_failed",
        "mcp_http_failed",
        "mcp_lab_gap",
        "mcp_lab_cursor_invalid",
        "mcp_lab_page_invalid",
        "mcp_lab_metadata_invalid",
        "mcp_lab_service_product_mismatch",
        "mcp_lab_record_invalid",
        "mcp_lab_derived_invalid",
        "mcp_lab_credential_required",
        "mcp_lab_ca_missing",
        "mcp_lab_proxy_invalid",
        "mcp_cursor_changed",
    ];
    let message = error.to_string();
    if message == "mcp_dns_destination_denied" {
        return "mcp_destination_denied";
    }
    SAFE.iter()
        .copied()
        .find(|code| *code == message)
        .unwrap_or("mcp_read_failed")
}

async fn capture(app: &App, source: &sqlx::postgres::PgRow) -> anyhow::Result<()> {
    let id: Uuid = source.get("id");
    let service: Uuid = source.get("service_id");
    let version: i32 = source.get("version");
    let capture_version: i32 = source.get("capture_version");
    let config: Value = source.get("config");
    let endpoint = config["endpoint"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("mcp_destination_denied"))?;
    let uri = config["resource_uri"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("mcp_resource_invalid"))?;
    let credential = match source.get::<Option<Vec<u8>>, _>("ciphertext") {
        Some(ciphertext) => Some(api::decrypt(
            app.config
                .master_key
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("mcp_master_required"))?,
            &ciphertext,
            &source.get::<Vec<u8>, _>("nonce"),
        )?),
        None => None,
    };
    if config["mode"] == "incremental_lab" {
        anyhow::ensure!(
            config["synthetic"] == false,
            "mcp_lab_configuration_invalid"
        );
        let ca_pem = config["ca_pem"].as_str();
        return capture_lab(
            app,
            id,
            service,
            version,
            capture_version,
            endpoint,
            uri,
            credential.as_deref(),
            ca_pem,
        )
        .await;
    }
    anyhow::ensure!(config["synthetic"] == true, "mcp_synthetic_required");
    let text = read_resource(endpoint, uri, credential.as_deref()).await?;
    let digest = hash(&text);
    let mut tx = app.pool.begin().await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(7616)")
        .fetch_one(&mut *tx)
        .await?;
    if !locked {
        return Ok(());
    }
    let active: Option<Uuid> = sqlx::query_scalar("SELECT s.id FROM sources s JOIN services v ON v.id=s.service_id WHERE s.id=$1 AND s.version=$2 AND s.enabled AND s.deleted_at IS NULL AND v.enabled AND v.deleted_at IS NULL FOR SHARE OF s,v").bind(id).bind(version).fetch_optional(&mut *tx).await?;
    anyhow::ensure!(active.is_some(), "mcp_source_changed");
    let previous: Option<String> = sqlx::query_scalar("SELECT content_hash FROM mcp_captures WHERE source_id=$1 AND source_version=$2 AND resource_uri=$3").bind(id).bind(capture_version).bind(uri).fetch_optional(&mut *tx).await?;
    if let Some(previous) = previous {
        anyhow::ensure!(previous == digest, "mcp_resource_changed");
        return Ok(());
    }
    let size: i64 =
        sqlx::query_scalar("SELECT coalesce(sum(byte_length),0)::bigint FROM text_records")
            .fetch_one(&mut *tx)
            .await?;
    anyhow::ensure!(
        size + text.len() as i64 <= 268435456,
        "mcp_record_storage_backpressure"
    );
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let external_id = format!("{uri}:{offset}");
        let record = review::preserve_external(
            &mut tx,
            app,
            id,
            service,
            capture_version,
            &external_id,
            line.as_bytes(),
        )
        .await?;
        sqlx::query("INSERT INTO mcp_record_locations(source_id,source_version,external_id,record_id,content_hash) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING").bind(id).bind(capture_version).bind(&external_id).bind(record).bind(hash(line)).execute(&mut *tx).await?;
        offset += line.len();
    }
    sqlx::query("INSERT INTO mcp_captures(source_id,source_version,resource_uri,content_hash) VALUES($1,$2,$3,$4)").bind(id).bind(capture_version).bind(uri).bind(digest).execute(&mut *tx).await?;
    db::emit(&mut tx, "source.status", id, version).await?;
    tx.commit().await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn capture_lab(
    app: &App,
    source_id: Uuid,
    service_id: Uuid,
    version: i32,
    capture_version: i32,
    endpoint: &str,
    uri: &str,
    credential: Option<&str>,
    ca_pem: Option<&str>,
) -> anyhow::Result<()> {
    anyhow::ensure!(lab_resource(uri).is_some(), "mcp_lab_resource_invalid");
    let url = lab_endpoint_shape(endpoint)?;
    let credential = credential.ok_or_else(|| anyhow::anyhow!("mcp_lab_credential_required"))?;
    let cursor: Option<String> = sqlx::query_scalar(
        "SELECT cursor FROM mcp_incremental_cursors WHERE source_id=$1 AND capture_version=$2",
    )
    .bind(source_id)
    .bind(capture_version)
    .fetch_optional(&app.pool)
    .await?
    .flatten();
    let requested_uri = cursor
        .as_ref()
        .map_or_else(|| uri.to_owned(), |c| format!("{uri}?cursor={c}"));
    let result = rpc(
        &lab_client(ca_pem.map(|s| s.as_bytes()))?,
        &url,
        Some(credential),
        "resources/read",
        json!({"uri":requested_uri}),
        100,
    )
    .await?;
    let contents = result["contents"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("mcp_contents_invalid"))?;
    anyhow::ensure!(
        contents.len() == 1
            && contents[0]["uri"] == requested_uri
            && contents[0]["mimeType"] == "application/json"
            && contents[0].get("blob").is_none(),
        "mcp_resource_mismatch"
    );
    let text = contents[0]["text"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("mcp_text_required"))?;
    anyhow::ensure!(text.len() <= MAX_TEXT_BYTES, "mcp_text_too_large");
    let page: Value = serde_json::from_str(text)?;
    let (product, software_version) = lab_metadata(&page, uri)?;
    let stream = uri.rsplit('/').next().unwrap_or("");
    anyhow::ensure!(
        page["schema_version"] == 1
            && page["source"] == stream
            && page["requested_cursor"] == json!(cursor)
            && page["has_more"].is_boolean(),
        "mcp_lab_page_invalid"
    );
    anyhow::ensure!(
        matches!(
            page["continuity"].as_str(),
            Some("initial" | "continuous" | "rotation")
        ),
        "mcp_lab_gap"
    );
    let next = page["next_cursor"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("mcp_lab_cursor_invalid"))?;
    anyhow::ensure!(
        !next.is_empty()
            && next.len() <= 1024
            && next
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
        "mcp_lab_cursor_invalid"
    );
    let records = page["records"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("mcp_lab_page_invalid"))?;
    anyhow::ensure!(records.len() <= 128, "mcp_lab_page_invalid");
    anyhow::ensure!(
        records.is_empty() || cursor.as_deref() != Some(next),
        "mcp_lab_cursor_invalid"
    );
    let mut total = 0usize;
    let mut plans: Vec<RecordPlan> = Vec::with_capacity(records.len());
    for record in records {
        let id = record["id"].as_str().unwrap_or("");
        let file_id = record["file_id"].as_str().unwrap_or("");
        let line = record["text"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("mcp_lab_record_invalid"))?;
        let start = record["start"].as_i64().unwrap_or(-1);
        let end = record["end"].as_i64().unwrap_or(-1);
        total = total.saturating_add(line.len());
        anyhow::ensure!(
            [id, file_id]
                .iter()
                .all(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                && line.ends_with('\n')
                && line.len() <= 16384
                && start >= 0
                && end.checked_sub(start) == Some(line.len() as i64)
                && record["sha256"] == hash(line)
                && total <= 65536,
            "mcp_lab_record_invalid"
        );
        // Los eventos derivados se validan antes de abrir la transacción:
        // un error de integridad aborta la captura sin tocar nada, como el
        // resto de validaciones de la página.
        plans.push(plan_record(
            uri,
            record,
            &product,
            software_version.as_deref(),
        )?);
    }
    let mut tx = app.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(7616)")
        .execute(&mut *tx)
        .await?;
    let active: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sources s JOIN services v ON v.id=s.service_id WHERE s.id=$1 AND s.version=$2 AND s.data_class='real' AND s.enabled AND s.deleted_at IS NULL AND v.enabled AND v.deleted_at IS NULL)").bind(source_id).bind(version).fetch_one(&mut *tx).await?;
    anyhow::ensure!(active, "mcp_source_changed");
    sqlx::query("INSERT INTO mcp_incremental_cursors(source_id,capture_version) VALUES($1,$2) ON CONFLICT DO NOTHING").bind(source_id).bind(capture_version).execute(&mut *tx).await?;
    let current: Option<String> = sqlx::query_scalar("SELECT cursor FROM mcp_incremental_cursors WHERE source_id=$1 AND capture_version=$2 FOR UPDATE").bind(source_id).bind(capture_version).fetch_one(&mut *tx).await?;
    anyhow::ensure!(current == cursor, "mcp_cursor_changed");
    if let Some(software_version) = software_version {
        let product_matches: bool = sqlx::query_scalar(
            "SELECT software_product IS NULL OR software_origin='mcp' OR software_product=$2 FROM services WHERE id=$1",
        )
        .bind(service_id)
        .bind(&product)
        .fetch_one(&mut *tx)
        .await?;
        anyhow::ensure!(product_matches, "mcp_lab_service_product_mismatch");
        sqlx::query("UPDATE services SET software_product=$2,software_version=$3,software_origin='mcp',updated_at=now() WHERE id=$1 AND (software_product IS DISTINCT FROM $2 OR software_version IS DISTINCT FROM $3 OR software_origin IS DISTINCT FROM 'mcp')")
            .bind(service_id).bind(product).bind(software_version).execute(&mut *tx).await?;
    } else {
        // version.json ausente o inválido: no se conserva una versión MCP
        // anterior. Solo se limpia lo que puso el propio MCP; una
        // declaración manual del operador nunca se toca.
        sqlx::query("UPDATE services SET software_product=NULL,software_version=NULL,software_origin=NULL,updated_at=now() WHERE id=$1 AND software_origin='mcp'")
            .bind(service_id).execute(&mut *tx).await?;
    }
    sqlx::query("INSERT INTO source_checks(source_id,source_version,result) VALUES($1,$2,$3) ON CONFLICT(source_id) DO UPDATE SET source_version=$2,checked_at=now(),result=$3")
        .bind(source_id).bind(version).bind(json!({"readable":true,"connection_attempted":true,"resource_uri":uri,"service":page["service"],"continuity":page["continuity"]})).execute(&mut *tx).await?;
    let stored: i64 = sqlx::query_scalar("SELECT real_queue_bytes()")
        .fetch_one(&mut *tx)
        .await?;
    anyhow::ensure!(
        stored.saturating_add((total as i64).saturating_mul(4)) <= 268435456,
        "mcp_record_storage_backpressure"
    );
    let run = Uuid::new_v5(&source_id, format!("mcp:{capture_version}").as_bytes());
    let service_name: Option<String> = if records.is_empty() {
        None
    } else {
        Some(
            sqlx::query_scalar("SELECT name FROM services WHERE id=$1")
                .bind(service_id)
                .fetch_one(&mut *tx)
                .await?,
        )
    };
    for (record, plan) in records.iter().zip(plans.iter()) {
        let external_id = record["id"].as_str().unwrap();
        let line = record["text"].as_str().unwrap();
        let bytes = line.as_bytes();
        let file_id = record["file_id"].as_str().unwrap();
        let start = record["start"].as_i64().unwrap();
        let end = record["end"].as_i64().unwrap();
        let digest = hash(bytes);
        let record_id = review::preserve_external(
            &mut tx,
            app,
            source_id,
            service_id,
            capture_version,
            external_id,
            bytes,
        )
        .await?;
        sqlx::query("INSERT INTO mcp_record_locations(source_id,source_version,external_id,record_id,content_hash,remote_file_id,byte_start,byte_end) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING")
            .bind(source_id).bind(capture_version).bind(external_id).bind(record_id).bind(&digest).bind(file_id).bind(start).bind(end).execute(&mut *tx).await?;
        match plan {
            RecordPlan::Derived(validation) => {
                let mut first: Option<DerivedRow> = None;
                for event in &validation.events {
                    let row =
                        derived_row(record_id, event, &app.config.session_id, chrono::Utc::now());
                    let seq: Option<i64> = sqlx::query_scalar("INSERT INTO events(id,run_id,external_event_id,source_id,file_instance_id,generation,byte_start,byte_end,line_hash,event_time,source,event_type,level,src_ip,user_alias,service,message,schema_version,parser,service_id,data_class,http,attributes) VALUES($1,$2,$3,$4,NULL,0,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,1,$16,$17,'real',$18,$19) ON CONFLICT(id) DO NOTHING RETURNING ingest_seq")
                        .bind(row.id).bind(run).bind(row.id).bind(source_id).bind(start).bind(end).bind(&digest).bind(row.event_time).bind(&row.source).bind(&row.event_type).bind(&row.level).bind(&row.src_ip).bind(&row.user_alias).bind(service_name.as_deref().unwrap_or("")).bind(&row.message).bind(&row.parser).bind(service_id).bind(&row.http).bind(&row.attributes).fetch_optional(&mut *tx).await?;
                    if let Some(seq) = seq {
                        sqlx::query(
                            "INSERT INTO detection_work(event_id,ingest_seq) VALUES($1,$2)",
                        )
                        .bind(row.id)
                        .bind(seq)
                        .execute(&mut *tx)
                        .await?;
                    }
                    if first.is_none() {
                        first = Some(row);
                    }
                }
                if let Some(row) = first {
                    // El primer evento aceptado enlaza el registro (cobertura
                    // lo cuenta como normalizado); si hubo problemas de
                    // enriquecimiento en hermanos, queda el diagnóstico.
                    sqlx::query("UPDATE text_records SET event_id=$2,event_time=$3,parser=$4,diagnostic=$5 WHERE id=$1")
                        .bind(record_id).bind(row.id).bind(row.event_time).bind(&row.parser)
                        .bind(validation.issues.then_some("mcp_derived_invalid"))
                        .execute(&mut *tx).await?;
                } else {
                    sqlx::query("UPDATE text_records SET diagnostic=$2 WHERE id=$1")
                        .bind(record_id)
                        .bind(if validation.issues {
                            "mcp_derived_invalid"
                        } else {
                            "mcp_lab_unparsed"
                        })
                        .execute(&mut *tx)
                        .await?;
                }
            }
            RecordPlan::LegacyFallback => {
                let native = log_formats::NativeSource {
                    schema_version: 1,
                    synthetic: false,
                    run_id: run,
                    sha256: file_id.into(),
                    year: 0,
                    timezone: "UTC".into(),
                };
                // Error-log severity does not prove an application failure; retain it for review.
                if let Ok((event, parser)) = log_formats::parse(bytes, &native, start) {
                    let access: Value = serde_json::from_str(line)?;
                    let path: String = access["path"]
                        .as_str()
                        .unwrap_or("")
                        .chars()
                        .take(128)
                        .collect();
                    let summary = format!(
                        "{} {} · HTTP {}",
                        access["method"].as_str().unwrap_or(""),
                        path,
                        access["status"].as_u64().unwrap_or(0)
                    );
                    let seq: Option<i64> = sqlx::query_scalar("INSERT INTO events(id,run_id,external_event_id,source_id,file_instance_id,generation,byte_start,byte_end,line_hash,event_time,source,event_type,level,src_ip,user_alias,service,message,schema_version,parser,service_id,data_class,http) VALUES($1,$2,$3,$4,NULL,0,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,1,$16,$17,'real',$18) ON CONFLICT(id) DO NOTHING RETURNING ingest_seq")
                        .bind(record_id).bind(run).bind(event.event_id).bind(source_id).bind(start).bind(end).bind(&digest).bind(event.timestamp).bind(&event.source).bind(&event.event_type).bind(&event.level).bind(&event.src_ip).bind(&event.user).bind(service_name.as_deref().unwrap_or("")).bind(contracts::redact(&summary,&app.config.session_id)).bind(parser).bind(service_id).bind(&event.http).fetch_optional(&mut *tx).await?;
                    if let Some(seq) = seq {
                        sqlx::query(
                            "INSERT INTO detection_work(event_id,ingest_seq) VALUES($1,$2)",
                        )
                        .bind(record_id)
                        .bind(seq)
                        .execute(&mut *tx)
                        .await?;
                    }
                    sqlx::query("UPDATE text_records SET event_id=$1,event_time=$2,parser=$3,diagnostic=NULL WHERE id=$1").bind(record_id).bind(event.timestamp).bind(parser).execute(&mut *tx).await?;
                } else {
                    sqlx::query(
                        "UPDATE text_records SET diagnostic='mcp_lab_unparsed' WHERE id=$1",
                    )
                    .bind(record_id)
                    .execute(&mut *tx)
                    .await?;
                }
            }
            RecordPlan::TextOnly => {
                sqlx::query("UPDATE text_records SET diagnostic='mcp_lab_unparsed' WHERE id=$1")
                    .bind(record_id)
                    .execute(&mut *tx)
                    .await?;
            }
        }
    }
    sqlx::query("UPDATE mcp_incremental_cursors SET cursor=$3,updated_at=now() WHERE source_id=$1 AND capture_version=$2").bind(source_id).bind(capture_version).bind(next).execute(&mut *tx).await?;
    db::emit(&mut tx, "source.status", source_id, version).await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        extract::{Path, State},
        http::{HeaderMap, StatusCode},
        response::{IntoResponse, Response},
        routing::post,
    };
    use std::sync::{Arc, Mutex};
    #[test]
    fn lab_endpoint_shape_accepts_only_private_lab_network_https_mcp() {
        assert!(lab_endpoint_shape("https://192.168.122.210/mcp").is_ok());
        // 10.0.0.5 es una IP privada pero no pertenece a la red de laboratorio (192.168.122.0/24 por defecto)
        assert!(lab_endpoint_shape("https://10.0.0.5/mcp").is_err());
        assert!(lab_endpoint_shape("http://192.168.122.210/mcp").is_err());
        assert!(lab_endpoint_shape("https://8.8.8.8/mcp").is_err());
        assert!(lab_endpoint_shape("https://192.168.122.210:8443/mcp").is_err());
        assert!(lab_endpoint_shape("https://192.168.122.210/otra").is_err());
        assert!(lab_endpoint_shape("https://usuario@192.168.122.210/mcp").is_err());
        assert!(lab_endpoint_shape("https://192.168.122.210/mcp?x=1").is_err());
        assert!(lab_endpoint_shape("https://lab.example.com/mcp").is_err());
    }

    #[test]
    fn is_in_lab_network_verifies_subnets() {
        assert!(is_in_lab_network("192.168.122.1".parse().unwrap()));
        assert!(is_in_lab_network("192.168.122.210".parse().unwrap()));
        assert!(!is_in_lab_network("192.168.123.1".parse().unwrap()));
        assert!(!is_in_lab_network("10.0.0.1".parse().unwrap()));
        assert!(!is_in_lab_network("172.16.0.1".parse().unwrap()));
    }

    const RESOURCE: &str = "logs://synthetic/nginx";
    #[derive(Clone, Default)]
    struct Fixture {
        calls: Arc<Mutex<Vec<String>>>,
    }
    async fn reply(
        State(state): State<Fixture>,
        Path(mode): Path<String>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Response {
        assert_eq!(headers["mcp-protocol-version"], PROTOCOL_VERSION);
        assert_eq!(
            body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
            PROTOCOL_VERSION
        );
        assert_eq!(
            body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"],
            json!({})
        );
        assert_eq!(headers["authorization"], "Bearer synthetic-fixture-only");
        let method = body["method"].as_str().unwrap();
        assert_eq!(headers["mcp-method"], method);
        assert!(matches!(method, "resources/list" | "resources/read"));
        state.calls.lock().unwrap().push(method.to_owned());
        if mode == "redirect" {
            return (
                StatusCode::FOUND,
                [("location", "http://127.0.0.1:1/forbidden")],
                "",
            )
                .into_response();
        }
        let id = body["id"].clone();
        let result = if method == "resources/list" {
            if mode == "repeated" {
                json!({"resultType":"complete","resources":[],"nextCursor":"same"})
            } else if mode == "paged" && body["params"].get("cursor").is_none() {
                json!({"resultType":"complete","resources":[],"nextCursor":"page2"})
            } else {
                json!({"resultType":"complete","resources":[{"uri":RESOURCE,"name":"Synthetic nginx"}]})
            }
        } else {
            assert_eq!(headers["mcp-name"], RESOURCE);
            assert_eq!(body["params"]["uri"], RESOURCE);
            match mode.as_str() {
                "binary" => {
                    json!({"resultType":"complete","contents":[{"uri":RESOURCE,"mimeType":"application/octet-stream","blob":"AA=="}]})
                }
                "mismatch" => {
                    json!({"resultType":"complete","contents":[{"uri":"file:///etc/passwd","text":"not fetched"}]})
                }
                "input" => {
                    json!({"resultType":"inputRequired","inputRequests":[{"method":"sampling/createMessage"}]})
                }
                "lines" => {
                    json!({"resultType":"complete","contents":[{"uri":RESOURCE,"text":"x\n".repeat(2001)}]})
                }
                "large" => {
                    json!({"resultType":"complete","contents":[{"uri":RESOURCE,"text":"x".repeat(MAX_TEXT_BYTES+1)}]})
                }
                _ => {
                    json!({"resultType":"complete","contents":[{"uri":RESOURCE,"mimeType":"text/plain","text":"synthetic line one\nsynthetic line two"}]})
                }
            }
        };
        let response = json!({"jsonrpc":"2.0","id":id,"result":result});
        if mode == "sse" {
            let notification =
                json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}});
            return ([("content-type","text/event-stream")],format!(": synthetic fixture\r\n\r\ndata: {notification}\r\n\r\nevent: message\r\ndata: {response}\r\n\r\n")).into_response();
        }
        if mode == "wrongid" {
            return Json(json!({"jsonrpc":"2.0","id":999,"result":result})).into_response();
        }
        Json(response).into_response()
    }
    async fn fixture() -> (String, Fixture, tokio::task::JoinHandle<()>) {
        let state = Fixture::default();
        let router = Router::new()
            .route("/{mode}", post(reply))
            .with_state(state.clone());
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", socket.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(socket, router).await.unwrap() });
        (origin, state, task)
    }
    #[tokio::test]
    async fn reads_json_sse_and_paged_resources_without_tools() {
        let (origin, state, task) = fixture().await;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        for mode in ["json", "sse", "paged"] {
            let url = reqwest::Url::parse(&format!("{origin}/{mode}")).unwrap();
            let text = read_with_client(&client, &url, RESOURCE, Some("synthetic-fixture-only"))
                .await
                .unwrap();
            assert_eq!(text, "synthetic line one\nsynthetic line two");
        }
        let calls = state.calls.lock().unwrap();
        assert_eq!(calls.iter().filter(|s| *s == "resources/read").count(), 3);
        assert_eq!(calls.iter().filter(|s| *s == "resources/list").count(), 4);
        task.abort();
    }
    #[tokio::test]
    async fn rejects_redirect_binary_resource_mismatch_interaction_repeat_and_size() {
        let (origin, _, task) = fixture().await;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        for (mode, reason) in [
            ("redirect", "mcp_http_failed"),
            ("binary", "mcp_resource_mismatch"),
            ("mismatch", "mcp_resource_mismatch"),
            ("input", "mcp_interaction_unsupported"),
            ("repeated", "mcp_cursor_repeated"),
            ("large", "mcp_text_too_large"),
            ("lines", "mcp_record_count_exceeded"),
            ("wrongid", "mcp_rpc_failed"),
        ] {
            let url = reqwest::Url::parse(&format!("{origin}/{mode}")).unwrap();
            let error = read_with_client(&client, &url, RESOURCE, Some("synthetic-fixture-only"))
                .await
                .unwrap_err();
            assert_eq!(error.to_string(), reason, "{mode}");
        }
        task.abort();
    }
    /// Página fixture del contrato de derivados: se procesa con el
    /// validador y el mapeo puros del backend (sin Postgres) y se comprueba
    /// el resultado por registro, la exclusión mutua y la idempotencia.
    fn derived_fixture_page() -> Value {
        json!({
            "schema_version": 1, "source": "auth", "requested_cursor": null,
            "records": [
                {"id": "a".repeat(64), "text": "Nov 22 01:02:03 lab sshd[812]: Failed password for invalid user admin from 192.168.122.1 port 51234 ssh2\n",
                 "derived_events": [{
                    "event_schema_version": 1, "event_type": "auth.failed", "source": "auth",
                    "level": "warning", "timestamp": "2026-11-22T01:02:03Z",
                    "timestamp_source": "syslog_context_year", "src_ip": "192.168.122.1",
                    "username": "admin", "parser_name": "openssh-auth", "parser_version": "1",
                    "attributes": {"auth_method": "password", "invalid_user": true, "protocol": "ssh"}
                 }]},
                {"id": "b".repeat(64), "text": "Nov 22 01:03:00 lab sshd[813]: Accepted publickey for lab-user from 192.168.122.1 port 51240 ssh2\n"}
            ],
            "service": {"id": "ssh", "product": "openbsd:openssh", "version": "9.9p1", "version_source": "service_status", "routes": []}
        })
    }
    fn record_id(source_id: Uuid, capture_version: i32, external_id: &str) -> Uuid {
        let run = Uuid::new_v5(&source_id, format!("mcp:{capture_version}").as_bytes());
        Uuid::new_v5(&run, external_id.as_bytes())
    }
    #[test]
    fn derived_page_plans_rows_and_mutual_exclusion() {
        let source_id = Uuid::new_v5(&Uuid::NAMESPACE_OID, b"source-fixture");
        let ingested = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let page = derived_fixture_page();
        let (product, version) = lab_metadata(&page, "logs://ssh/auth").unwrap();
        let version = version.as_deref();
        let records = page["records"].as_array().unwrap();
        // Registro SSH con derivados: plan Derived y una fila auth.failed.
        let plan = plan_record("logs://ssh/auth", &records[0], &product, version).unwrap();
        let RecordPlan::Derived(validation) = plan else {
            panic!("se esperaba plan Derived")
        };
        assert_eq!(validation.events.len(), 1);
        assert!(!validation.issues);
        let rid = record_id(source_id, 3, &"a".repeat(64));
        let row = derived_row(rid, &validation.events[0], "session-fixture", ingested);
        assert_eq!(row.event_type, "auth.failed");
        assert_eq!(row.parser, "openssh-auth@1");
        assert_eq!(row.src_ip.as_deref(), Some("192.168.122.1"));
        assert!(row.user_alias.as_deref().unwrap().starts_with("usuario-"));
        assert!(
            !row.message.contains("admin"),
            "el mensaje no filtra el usuario crudo"
        );
        assert_eq!(
            row.event_time,
            chrono::DateTime::parse_from_rfc3339("2026-11-22T01:02:03Z")
                .unwrap()
                .with_timezone(&chrono::Utc)
        );
        // Idempotencia: releer la misma página produce la misma identidad.
        let plan2 = plan_record("logs://ssh/auth", &records[0], &product, version).unwrap();
        let RecordPlan::Derived(validation2) = plan2 else {
            panic!("se esperaba plan Derived")
        };
        let row2 = derived_row(rid, &validation2.events[0], "session-fixture", ingested);
        assert_eq!(row.id, row2.id);
        // Registro SSH sin derivados: texto, exactamente como hoy.
        assert!(matches!(
            plan_record("logs://ssh/auth", &records[1], &product, version).unwrap(),
            RecordPlan::TextOnly
        ));
        // Nginx access sin derivados: fallback legacy; con derivados (aunque
        // todos sean inválidos): manda el adaptador y no hay fallback.
        let plain_access = json!({"id": "c".repeat(64), "text": "{}\n"});
        assert!(matches!(
            plan_record(
                "logs://nginx/access",
                &plain_access,
                "f5:nginx",
                Some("1.27.5")
            )
            .unwrap(),
            RecordPlan::LegacyFallback
        ));
        let invalid_derived = json!({"id": "d".repeat(64), "text": "{}\n",
            "derived_events": [{"event_schema_version": 99}]});
        let plan = plan_record(
            "logs://nginx/access",
            &invalid_derived,
            "f5:nginx",
            Some("1.27.5"),
        )
        .unwrap();
        let RecordPlan::Derived(validation) = plan else {
            panic!("derivado presente debe mandar sobre el fallback")
        };
        assert!(validation.events.is_empty() && validation.issues);
        // Suplantación de servicio en un evento: error de integridad.
        let spoofed = json!({"id": "e".repeat(64), "text": "x\n",
            "derived_events": [{"service": "mysql"}]});
        assert_eq!(
            plan_record("logs://ssh/auth", &spoofed, &product, version)
                .unwrap_err()
                .to_string(),
            "mcp_lab_derived_invalid"
        );
        // derived_events que no es un array también es integridad.
        let not_array = json!({"id": "f".repeat(64), "text": "x\n", "derived_events": {}});
        assert_eq!(
            plan_record("logs://ssh/auth", &not_array, &product, version)
                .unwrap_err()
                .to_string(),
            "mcp_lab_derived_invalid"
        );
    }
    fn metadata_page(service: &str, product: &str, version: Value, source: &str) -> Value {
        json!({"schema_version": 1, "records": [], "service": {
            "id": service, "product": product, "version": version,
            "version_source": source, "routes": []
        }})
    }

    #[test]
    fn lab_metadata_accepts_each_resource_with_its_fixed_product() {
        // Los siete recursos y sus productos permitidos: el CPE jamás sale
        // del contenido del log. MySQL admite Oracle MySQL y MariaDB; el
        // resto tiene un único producto.
        for (uri, service, product) in [
            ("logs://nginx/access", "nginx", "f5:nginx"),
            ("logs://nginx/error", "nginx", "f5:nginx"),
            ("logs://mysql/error", "mysql", "oracle:mysql"),
            ("logs://mysql/error", "mysql", "mariadb:mariadb"),
            ("logs://mysql/audit", "mysql", "oracle:mysql"),
            ("logs://mysql/audit", "mysql", "mariadb:mariadb"),
            ("logs://node/app", "node", "nodejs:node.js"),
            ("logs://node/security", "node", "nodejs:node.js"),
            ("logs://ssh/auth", "ssh", "openbsd:openssh"),
        ] {
            let page = metadata_page(service, product, json!("1.2.3"), "service_status");
            assert_eq!(
                lab_metadata(&page, uri).unwrap(),
                (product.to_owned(), Some("1.2.3".to_owned())),
                "{uri}"
            );
        }
        // Recurso fuera de la lista fija: denegado.
        assert!(
            lab_metadata(
                &metadata_page("nginx", "f5:nginx", json!("1.2.3"), "service_status"),
                "logs://nginx/status"
            )
            .is_err()
        );
    }

    #[test]
    fn lab_metadata_version_update_flows_and_both_resources_converge() {
        // Versión inicial A y, tras una actualización del servicio, B: el
        // tramo puro devuelve cada vez la versión de la página; la
        // persistencia (SQL) compara y actualiza solo si cambió.
        let page_a = metadata_page("nginx", "f5:nginx", json!("1.26.3"), "service_status");
        let page_b = metadata_page("nginx", "f5:nginx", json!("1.27.5"), "service_status");
        assert_eq!(
            lab_metadata(&page_a, "logs://nginx/access").unwrap(),
            ("f5:nginx".to_owned(), Some("1.26.3".to_owned()))
        );
        assert_eq!(
            lab_metadata(&page_b, "logs://nginx/access").unwrap(),
            ("f5:nginx".to_owned(), Some("1.27.5".to_owned()))
        );
        // access y error son dos fuentes del MISMO servicio: convergen en
        // la misma versión publicada; un fallo de una no borra la otra
        // porque la actualización ocurre dentro de la captura sana.
        assert_eq!(
            lab_metadata(&page_b, "logs://nginx/error").unwrap(),
            lab_metadata(&page_b, "logs://nginx/access").unwrap()
        );
    }

    #[test]
    fn lab_metadata_missing_version_keeps_product_and_no_version() {
        // version.json ausente o ilegible en la VM: el servidor publica
        // version null + version_source "unavailable". No es un error de
        // integridad: el backend recibe el producto con versión ausente y
        // solo limpia lo que el propio MCP hubiera puesto antes. El
        // producto sí se conserva y se valida aunque falte la versión.
        let page = metadata_page("mysql", "mariadb:mariadb", Value::Null, "unavailable");
        assert_eq!(
            lab_metadata(&page, "logs://mysql/error").unwrap(),
            ("mariadb:mariadb".to_owned(), None)
        );
    }

    #[test]
    fn mariadb_product_flows_to_derived_validation() {
        let page = metadata_page(
            "mysql",
            "mariadb:mariadb",
            json!("11.8.9"),
            "service_status",
        );
        let (product, version) = lab_metadata(&page, "logs://mysql/audit").unwrap();
        assert_eq!(product, "mariadb:mariadb");
        assert_eq!(version.as_deref(), Some("11.8.9"));
        let record = json!({"id": "a".repeat(64), "text": "x\n", "derived_events": [{
            "event_schema_version": 1, "event_type": "app.error", "source": "app",
            "level": "error", "parser_name": "mysql-error", "parser_version": "1"
        }]});
        let plan =
            plan_record("logs://mysql/audit", &record, &product, version.as_deref()).unwrap();
        let RecordPlan::Derived(validation) = plan else {
            panic!("se esperaba plan Derived")
        };
        assert_eq!(validation.events.len(), 1);
        // Un evento que reclame otro producto es integridad: el producto
        // autenticado de la página manda, no el texto del log.
        let spoofed = json!({"id": "b".repeat(64), "text": "x\n", "derived_events": [{
            "event_schema_version": 1, "event_type": "app.error", "source": "app",
            "level": "error", "product": "oracle:mysql",
            "parser_name": "mysql-error", "parser_version": "1"
        }]});
        assert_eq!(
            plan_record("logs://mysql/audit", &spoofed, &product, version.as_deref())
                .unwrap_err()
                .to_string(),
            "mcp_lab_derived_invalid"
        );
    }

    #[test]
    fn lab_metadata_rejects_invalid_or_spoofed_documents() {
        let uri = "logs://ssh/auth";
        // Producto distinto del esperado para el recurso (p. ej. el
        // documento de otro servicio copiado al directorio equivocado).
        let wrong_product = metadata_page("ssh", "f5:nginx", json!("9.6p1"), "service_status");
        assert!(lab_metadata(&wrong_product, uri).is_err());
        // MySQL solo admite sus dos productos reales; uno ajeno se rechaza.
        let wrong_mysql = metadata_page("mysql", "f5:nginx", json!("11.8.9"), "service_status");
        assert!(lab_metadata(&wrong_mysql, "logs://mysql/error").is_err());
        // Identificador de servicio distinto del recurso.
        let wrong_id = metadata_page("nginx", "openbsd:openssh", json!("9.6p1"), "service_status");
        assert!(lab_metadata(&wrong_id, uri).is_err());
        // Versión con caracteres fuera del contrato (espacio, comillas).
        let bad_version =
            metadata_page("ssh", "openbsd:openssh", json!("9.6 p1"), "service_status");
        assert!(lab_metadata(&bad_version, uri).is_err());
        // Versión presente pero fuente que no es el estado del servicio.
        let bad_source = metadata_page("ssh", "openbsd:openssh", json!("9.6p1"), "banner");
        assert!(lab_metadata(&bad_source, uri).is_err());
        // Clave extra en el objeto service: el esquema es cerrado.
        let mut extra = metadata_page("ssh", "openbsd:openssh", json!("9.6p1"), "service_status");
        extra["service"]["extra"] = json!(true);
        assert!(lab_metadata(&extra, uri).is_err());
        // Ruta informativa inválida (no empieza por /).
        let mut bad_routes =
            metadata_page("ssh", "openbsd:openssh", json!("9.6p1"), "service_status");
        bad_routes["service"]["routes"] = json!(["etc/passwd"]);
        assert!(lab_metadata(&bad_routes, uri).is_err());
    }

    #[test]
    fn request_id_correlates_across_resources_and_nginx_format_has_none() {
        // Correlación por identificador compartido (Etapa 7): dos canales
        // Node distintos (app y security) emiten eventos con el mismo
        // request_id; tras validar y mapear, ambas filas conservan el
        // MISMO attributes.request_id, cada una con su parser y tipo. La
        // procedencia por servicio la fija la fuente autenticada en la
        // captura (service_id), no el contenido: nada se mezcla.
        let ingested = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let mk = |parser: &str, event_type: &str, source: &str| {
            json!({"id": "a".repeat(64), "text": "{}\n", "derived_events": [{
                "event_schema_version": 1, "event_type": event_type, "source": source,
                "level": "info", "timestamp": "2026-11-22T01:04:00Z",
                "timestamp_source": "producer_rfc3339",
                "parser_name": parser, "parser_version": "1",
                "attributes": {"request_id": "req-a20"}
            }]})
        };
        let app_rec = mk("node-json", "app.error", "app");
        let sec_rec = mk("node-json", "system.notice", "system");
        let mut request_ids = Vec::new();
        for (uri, rec) in [
            ("logs://node/app", &app_rec),
            ("logs://node/security", &sec_rec),
        ] {
            let plan = plan_record(uri, rec, "nodejs:node.js", Some("22.5.1")).unwrap();
            let RecordPlan::Derived(validation) = plan else {
                panic!("se esperaba plan Derived para {uri}")
            };
            let row = derived_row(Uuid::nil(), &validation.events[0], "s", ingested);
            request_ids.push(
                row.attributes
                    .as_ref()
                    .and_then(|a| a["request_id"].as_str())
                    .map(str::to_owned),
            );
        }
        assert_eq!(
            request_ids,
            vec![Some("req-a20".into()), Some("req-a20".into())]
        );
        // El formato real del access del laboratorio NO trae request_id
        // (conjunto cerrado de claves de parse_lab_access): el adaptador
        // no lo inventa y la fila legacy no lleva attributes. La
        // correlación Nginx→Node por request_id requiere que el formato
        // del access lo incluya en origen; hoy no es el caso y queda
        // documentado, no simulado.
        let access = json!({"id": "b".repeat(64), "text": "{}\n"});
        assert!(matches!(
            plan_record("logs://nginx/access", &access, "f5:nginx", Some("1.26.3")).unwrap(),
            RecordPlan::LegacyFallback
        ));
    }

    #[test]
    fn derived_row_pseudonymizes_db_user_and_keeps_request_id() {
        let event = contracts::DerivedEvent {
            index: 0,
            event_type: "system.notice".into(),
            source: "system".into(),
            level: "info".into(),
            timestamp: None,
            timestamp_source: None,
            src_ip: None,
            username: None,
            http: None,
            parser_name: "mysql-audit".into(),
            parser_version: "1".into(),
            attributes: Some(
                json!({"operation": "QUERY", "db_user": "root", "request_id": "req-42"}),
            ),
        };
        let ingested = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let row = derived_row(Uuid::nil(), &event, "session-fixture", ingested);
        let attributes = row.attributes.unwrap();
        assert_eq!(attributes["request_id"], json!("req-42"));
        assert!(
            attributes["db_user"]
                .as_str()
                .unwrap()
                .starts_with("usuario-")
        );
        assert!(!attributes.to_string().contains("\"root\""));
        // Sin timestamp del adaptador, event_time es el de ingesta.
        assert_eq!(row.event_time, ingested);
        assert_eq!(row.message, "system.notice");
    }
    #[test]
    fn destination_and_server_requests_are_denied() {
        for endpoint in [
            "http://localhost:8090/mcp",
            "https://127.0.0.1/mcp",
            "https://169.254.169.254/mcp",
            "file:///etc/passwd",
            "https://secret@example.test/mcp",
            "https://example.test/mcp?key=secret",
            "https://example.test:444/mcp",
            "https://example.test/mcp#fragment",
        ] {
            assert!(validate_endpoint(endpoint).is_err(), "{endpoint}");
        }
        assert!(
            rpc_result(
                json!({"jsonrpc":"2.0","id":1,"method":"sampling/createMessage"}),
                1
            )
            .is_err()
        );
        assert_eq!(
            header_name("logs://synthetic/test"),
            "logs://synthetic/test"
        );
        assert_eq!(header_name("ñ"), "=?base64?w7E=?=");
        assert!(frame_result(b"data: {invalid}", 1).is_err());
        assert_eq!(
            safe_error(&anyhow::anyhow!("secret-body-canary")),
            "mcp_read_failed"
        );
        assert_eq!(
            safe_error(&anyhow::anyhow!("mcp_record_count_exceeded")),
            "mcp_record_count_exceeded"
        );
    }
}
