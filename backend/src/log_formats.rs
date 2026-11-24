//! Readers for original synthetic files; normalization stays inside the backend.
use crate::{contracts::LogEvent, hash};
use chrono::{NaiveDateTime, TimeZone, Utc};
use serde::Deserialize;
use std::{io::Read, path::Path};
use uuid::Uuid;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSource {
    pub schema_version: u8,
    pub synthetic: bool,
    pub run_id: Uuid,
    pub sha256: String,
    pub year: i32,
    pub timezone: String,
}
pub fn source(path: &Path) -> anyhow::Result<NativeSource> {
    source_in_root(
        path,
        path.parent()
            .ok_or_else(|| anyhow::anyhow!("native_source_invalid"))?,
    )
}
pub fn source_in_root(path: &Path, root: &Path) -> anyhow::Result<NativeSource> {
    let sidecar = path.with_extension("source.json");
    let f = crate::collector::safe_regular(&sidecar, root)?;
    anyhow::ensure!(
        f.metadata()?.is_file() && f.metadata()?.len() <= 16384,
        "native_source_invalid"
    );
    let mut bytes = Vec::new();
    f.take(16385).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 16384, "native_source_invalid");
    let s: NativeSource = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(
        s.schema_version == 1
            && s.synthetic
            && s.timezone == "UTC"
            && (1970..=2100).contains(&s.year),
        "native_source_invalid"
    );
    Ok(s)
}
pub fn verify(file: &mut std::fs::File, source: &NativeSource) -> anyhow::Result<()> {
    use sha2::Digest;
    use std::io::{Seek, SeekFrom};
    let mut digest = sha2::Sha256::new();
    let mut buffer = [0; 8192];
    file.seek(SeekFrom::Start(0))?;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    anyhow::ensure!(
        hex::encode(digest.finalize()) == source.sha256,
        "native_source_hash_mismatch"
    );
    file.seek(SeekFrom::Start(0))?;
    Ok(())
}
pub fn parse(
    bytes: &[u8],
    source: &NativeSource,
    offset: i64,
) -> anyhow::Result<(LogEvent, &'static str)> {
    let line = std::str::from_utf8(bytes)?.trim_end_matches(['\r', '\n']);
    anyhow::ensure!(
        !line.is_empty() && line.chars().count() <= 2048,
        "native_record_too_large"
    );
    if !source.synthetic && line.starts_with('{') {
        return parse_lab_access(line, source, offset);
    }
    let nginx = regex::Regex::new(
        r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(error|crit|alert|emerg|warn|notice|info|debug)\] ",
    )?;
    let apache = regex::Regex::new(
        r"^\[([^\]]+)\] \[([^\]]+):(error|crit|alert|emerg|warn|notice|info|debug)\] ",
    )?;
    let auth =
        regex::Regex::new(r"^([A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) \S+ sshd\[\d+\]: (.*)$")?;
    let (mut http_method, mut http_raw_target, mut http_status) =
        (String::new(), String::new(), 0i64);
    let (timestamp, parser, service, source_kind, event_type, level, user, ip) = if let Some(c) =
        nginx.captures(line)
    {
        let t = NaiveDateTime::parse_from_str(&c[1], "%Y/%m/%d %H:%M:%S")?;
        let error = matches!(&c[2], "error" | "crit" | "alert" | "emerg");
        (
            t,
            "nginx-error",
            "nginx",
            "app",
            if error { "app.error" } else { "system.notice" },
            if error { "error" } else { "info" },
            None,
            None,
        )
    } else if let Some(c) = apache.captures(line) {
        let t = NaiveDateTime::parse_from_str(&c[1], "%a %b %d %H:%M:%S%.f %Y")?;
        let error = matches!(&c[3], "error" | "crit" | "alert" | "emerg");
        (
            t,
            "apache-error",
            "apache-httpd",
            "app",
            if error { "app.error" } else { "system.notice" },
            if error { "error" } else { "info" },
            None,
            None,
        )
    } else if let Some(c) = regex::Regex::new(r#"^(\S+) \S+ \S+ \[([^\]]+)\] "(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH) (\S+) HTTP/[0-9.]+" (\d{3}) \S+"#)?.captures(line) {
        let t = chrono::DateTime::parse_from_str(&c[2], "%d/%b/%Y:%H:%M:%S %z")?.naive_utc();
        let status: u16 = c[4].parse()?;
        anyhow::ensure!((100..=599).contains(&status), "http_status_invalid");
        http_raw_target = c[3].split('?').next().unwrap_or("").to_string();
        http_method = c[0].split('"').nth(1).and_then(|r| r.split(' ').next()).unwrap_or("GET").to_string();
        http_status = status as i64;
        let path = http_raw_target.to_ascii_lowercase();
        let suspicious = ["/.env", "/.git/", "/wp-admin", "/wp-login.php", "/phpmyadmin", "/etc/passwd"].iter().any(|prefix| path.starts_with(prefix));
        (t, "http-access", "http", if suspicious { "app" } else { "system" }, if suspicious { "http.suspicious" } else { "system.notice" }, if suspicious { "warning" } else { "info" }, None, Some(c[1].to_owned()))
    } else if let Some(c) = regex::Regex::new(r"^<([0-9]{1,3})>1 (\S+) \S+ \S+ ")?.captures(line) {
        let priority: u16 = c[1].parse()?;
        anyhow::ensure!(priority <= 191, "syslog_priority_invalid");
        let t = chrono::DateTime::parse_from_rfc3339(&c[2])?.naive_utc();
        (t, "syslog-rfc5424", "system-journal", "system", "system.notice", if priority % 8 <= 3 { "error" } else { "info" }, None, None)
    } else if let Some(c) = regex::Regex::new(r"^\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ haproxy\[\d+\]: \S+ \[([^\]]+)\] \S+ \S+ [0-9/+-]+ ([0-9]{3}) ")?.captures(line) {
        let t = NaiveDateTime::parse_from_str(&c[1], "%d/%b/%Y:%H:%M:%S%.f")?;
        let status: u16 = c[2].parse()?;
        anyhow::ensure!((100..=599).contains(&status), "http_status_invalid");
        (t, "haproxy-http", "haproxy", "app", if status >= 500 { "app.error" } else { "system.notice" }, if status >= 500 { "error" } else { "info" }, None, None)
    } else if let Some(c) = auth.captures(line) {
        anyhow::ensure!((1970..=2100).contains(&source.year), "ssh_year_required");
        let t = NaiveDateTime::parse_from_str(
            &format!("{} {}", source.year, &c[1]),
            "%Y %b %e %H:%M:%S",
        )?;
        let fields = regex::Regex::new(
            r"^(Failed password for (?:invalid user )?|Accepted (?:password|publickey) for |Invalid user )(\S+) (?:from )(\S+)",
        )?;
        let f = fields
            .captures(&c[2])
            .ok_or_else(|| anyhow::anyhow!("native_record_unsupported"))?;
        let success = c[2].starts_with("Accepted ");
        (
            t,
            "ssh-auth",
            "sshd",
            "auth",
            if success {
                "auth.success"
            } else {
                "auth.failed"
            },
            if success { "info" } else { "warning" },
            Some(format!("demo-{}", &hash(&f[2])[..16])),
            Some(f[3].to_owned()),
        )
    } else {
        anyhow::bail!("native_record_unsupported")
    };
    // Notices retain their semantic category, rather than becoming application errors.
    let source_kind = if event_type == "system.notice" {
        "system"
    } else {
        source_kind
    };
    let http_evidence = if parser == "http-access" {
        // El formato combinado conserva la línea de solicitud tal como llegó
        // (target crudo, sin query); la normalización del servidor no consta.
        Some(
            serde_json::json!({"method":http_method,"raw_target":http_raw_target,"status":http_status,"origin":"raw_only"}),
        )
    } else {
        None
    };
    let event = LogEvent {
        schema_version: 1,
        scenario_run_id: source.run_id,
        event_id: Uuid::new_v5(
            &source.run_id,
            format!("{}:{offset}", source.sha256).as_bytes(),
        ),
        seq: offset as u64 + 1,
        timestamp: Utc.from_utc_datetime(&timestamp),
        source: source_kind.into(),
        event_type: event_type.into(),
        level: level.into(),
        message: line.into(),
        src_ip: ip,
        user,
        service: Some(service.into()),
        request_id: None,
        http: http_evidence,
    };
    // Reuse the existing synthetic-IP and field validation at the trust boundary.
    crate::contracts::parse_line_with_class(&serde_json::to_vec(&event)?, !source.synthetic)?;
    Ok((event, parser))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LabAccess {
    timestamp: chrono::DateTime<Utc>,
    remote_addr: std::net::IpAddr,
    remote_user: String,
    method: String,
    path: String,
    status: u16,
    upstream_status: String,
    protected: String,
}

fn parse_lab_access(
    line: &str,
    source: &NativeSource,
    offset: i64,
) -> anyhow::Result<(LogEvent, &'static str)> {
    let entry: LabAccess = serde_json::from_str(line)?;
    anyhow::ensure!(
        offset >= 0
            && (100..=599).contains(&entry.status)
            && matches!(entry.protected.as_str(), "basic" | "no")
            && matches!(
                entry.method.as_str(),
                "GET" | "POST" | "HEAD" | "PUT" | "DELETE" | "OPTIONS" | "PATCH"
            )
            && entry.path.starts_with('/')
            && entry.path.len() <= 1024
            && entry.remote_user.len() <= 64
            && entry.upstream_status.len() <= 64,
        "lab_access_invalid"
    );
    let user = (!entry.remote_user.is_empty() && entry.remote_user != "-")
        .then(|| format!("usuario-{}", &hash(&entry.remote_user)[..16]));
    let (category, kind, level) =
        if entry.protected == "basic" && user.is_some() && entry.status == 401 {
            ("auth", "auth.failed", "warning")
        } else if entry.protected == "basic" && user.is_some() && (200..300).contains(&entry.status)
        {
            ("auth", "auth.success", "info")
        } else if entry.status >= 500
            && entry.upstream_status.split(',').any(|s| {
                s.trim()
                    .parse::<u16>()
                    .is_ok_and(|n| (500..=599).contains(&n))
            })
        {
            ("app", "app.error", "error")
        } else {
            ("system", "system.notice", "info")
        };
    let event = LogEvent {
        schema_version: 1,
        scenario_run_id: source.run_id,
        event_id: Uuid::new_v5(
            &source.run_id,
            format!("{}:{offset}", source.sha256).as_bytes(),
        ),
        seq: offset as u64 + 1,
        timestamp: entry.timestamp,
        source: category.into(),
        event_type: kind.into(),
        level: level.into(),
        message: line.into(),
        src_ip: Some(entry.remote_addr.to_string()),
        user,
        service: Some("nginx".into()),
        request_id: None,
        // El JSON del laboratorio trae la ruta ya normalizada por Nginx
        // ($uri): no existe target crudo y no se reconstruye.
        http: Some(
            serde_json::json!({"method":entry.method,"normalized_path":entry.path.split('?').next().unwrap_or(""),"status":entry.status,"origin":"server_normalized_only"}),
        ),
    };
    crate::contracts::parse_line_with_class(&serde_json::to_vec(&event)?, true)?;
    Ok((event, "nginx-lab-json"))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn src() -> NativeSource {
        NativeSource {
            schema_version: 1,
            synthetic: true,
            run_id: Uuid::nil(),
            sha256: "fixture".into(),
            year: 2026,
            timezone: "UTC".into(),
        }
    }
    #[test]
    fn real_ssh_requires_explicit_year_and_accepts_private_ip() {
        let mut source = src();
        source.synthetic = false;
        source.year = 0;
        let line=b"Mar 15 02:00:01 server sshd[3821]: Failed password for root from 10.0.0.10 port 54100 ssh2";
        assert!(parse(line, &source, 0).is_err());
        source.year = 2026;
        let (event, parser) = parse(line, &source, 0).unwrap();
        assert_eq!(parser, "ssh-auth");
        assert_eq!(event.src_ip.as_deref(), Some("10.0.0.10"));
        source.synthetic = true;
        assert!(parse(line, &source, 0).is_err());
    }
    #[test]
    fn lab_http_does_not_turn_every_401_or_5xx_into_an_attack() {
        let mut source = src();
        source.synthetic = false;
        let line = |status, protected, user, upstream| {
            format!(
                r#"{{"timestamp":"2026-11-17T12:00:00Z","remote_addr":"10.0.0.2","remote_user":"{user}","method":"GET","path":"/secure/","status":{status},"upstream_status":"{upstream}","protected":"{protected}"}}"#
            )
        };
        let cases = [
            (line(401, "no", "alice", "-"), "system.notice"),
            (line(401, "basic", "-", "-"), "system.notice"),
            (line(401, "basic", "alice", "-"), "auth.failed"),
            (line(200, "basic", "alice", "200"), "auth.success"),
            (line(503, "no", "-", "503"), "app.error"),
            (line(503, "no", "-", "-"), "system.notice"),
        ];
        for (text, expected) in cases {
            assert_eq!(
                parse(text.as_bytes(), &source, 0).unwrap().0.event_type,
                expected
            );
        }
        assert!(parse(line(200, "basic", "alice", "200").as_bytes(), &src(), 0).is_err());
    }
    #[test]
    fn http_access_requires_sensitive_path_not_status_alone() {
        let normal =
            br#"198.51.100.7 - - [12/Nov/2026:12:00:00 +0000] "GET /home HTTP/1.1" 404 123"#;
        let suspicious =
            br#"198.51.100.7 - - [12/Nov/2026:12:00:00 +0000] "GET /.env HTTP/1.1" 404 123"#;
        assert_eq!(
            parse(normal, &src(), 0).unwrap().0.event_type,
            "system.notice"
        );
        let event = parse(suspicious, &src(), 1).unwrap().0;
        assert_eq!(event.event_type, "http.suspicious");
        assert_eq!(event.src_ip.as_deref(), Some("198.51.100.7"));
    }
    #[test]
    fn native_formats_keep_original_and_identity() {
        for (line, format, kind) in [
            (
                "<134>1 2024-03-15T02:10:01.000Z firewall-01 kernel - - [BLOCK] SRC=198.51.100.26",
                "syslog-rfc5424",
                "system.notice",
            ),
            (
                "Jan 15 14:30:01 lb-01 haproxy[1234]: 198.51.100.25:55001 [15/Jan/2024:14:30:01.000] frontend-https backend-api/app-01 1/0/2/45/48 503 89",
                "haproxy-http",
                "app.error",
            ),
            (
                "2026/10/27 03:41:10 [error] 1#1: upstream connection refused",
                "nginx-error",
                "app.error",
            ),
            (
                "[Tue Oct 27 03:41:10.204511 2026] [core:error] missing file",
                "apache-error",
                "app.error",
            ),
            (
                "Mar 15 02:00:01 web-01 sshd[3821]: Failed password for root from 198.51.100.26 port 54100 ssh2",
                "ssh-auth",
                "auth.failed",
            ),
            (
                "Mar 15 02:00:02 web-01 sshd[3821]: Accepted password for root from 198.51.100.26 port 54100 ssh2",
                "ssh-auth",
                "auth.success",
            ),
        ] {
            let (event, parser) = parse(line.as_bytes(), &src(), 0).unwrap();
            assert_eq!(parser, format);
            assert_eq!(event.event_type, kind);
            assert_eq!(event.message, line);
            assert_eq!(
                event.event_id,
                parse(line.as_bytes(), &src(), 0).unwrap().0.event_id
            );
            assert_ne!(
                event.event_id,
                parse(line.as_bytes(), &src(), 1).unwrap().0.event_id
            );
        }
        assert!(parse(b"unrecognized text", &src(), 0).is_err());
        assert!(
            parse(
                b"Mar 15 02:00:01 web sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2",
                &src(),
                0
            )
            .is_err()
        );
    }
}
