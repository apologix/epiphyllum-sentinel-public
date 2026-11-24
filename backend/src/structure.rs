use crate::{App, api::ApiError, db, hash, observability};
use axum::http::StatusCode;
use serde_json::{Value, json};
use sqlx::Row;
use std::path::{Path, PathBuf};
use uuid::Uuid;

type Result<T> = std::result::Result<T, ApiError>;
fn invalid() -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, "invalid_request")
}
fn not_found() -> ApiError {
    ApiError(StatusCode::NOT_FOUND, "not_found")
}

/// Mapa de estructura (STR-01): solo metadatos. El recorrido usa listado de
/// directorios y `symlink_metadata`; nunca abre un archivo, nunca calcula
/// hash y nunca sigue enlaces simbólicos. Lo ejecuta el backend, no el modelo.
pub const MAX_DEPTH: usize = 6;
pub const MAX_NODES: usize = 2000;
const PRUNE_DIRS: [&str; 4] = ["node_modules", ".git", "target", "__pycache__"];
const EXCLUDED_MARKERS: [&str; 10] = [
    ".env",
    "secret",
    "credential",
    "credencial",
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    "shadow",
    "id_rsa",
];

/// Un nombre con marcadores sensibles ni siquiera se lista.
pub fn excluded_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    EXCLUDED_MARKERS.iter().any(|m| lower.contains(m))
}

fn valid_directory(directory: &str) -> bool {
    directory.is_empty()
        || (directory.len() <= 64
            && directory
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)))
}

fn mode_string(metadata: &std::fs::Metadata) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        format!("{:04o}", metadata.permissions().mode() & 0o7777)
    }
    #[cfg(not(unix))]
    {
        String::new()
    }
}

fn mtime_secs(metadata: &std::fs::Metadata) -> i64 {
    metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Recorre `base` acumulando nodos {path, kind, size, mtime, mode} ordenados
/// por ruta. `truncated` queda en true si algún límite dejó parte sin mapear.
pub fn scan_tree(base: &Path) -> (Vec<Value>, bool) {
    let mut nodes: Vec<Value> = Vec::new();
    let mut truncated = false;
    // Pila de (ruta absoluta, ruta relativa, profundidad). La raíz es "".
    let mut stack: Vec<(PathBuf, String, usize)> = vec![(base.to_path_buf(), String::new(), 0)];
    while let Some((dir, rel, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut items: Vec<_> = entries.flatten().collect();
        items.sort_by_key(|e| e.file_name());
        for entry in items {
            if nodes.len() >= MAX_NODES {
                truncated = true;
                break;
            }
            let Ok(name) = entry.file_name().into_string() else {
                continue; // nombre no UTF-8: se omite, no se puede citar con seguridad
            };
            if excluded_name(&name) {
                continue;
            }
            let Ok(metadata) = entry.path().symlink_metadata() else {
                continue;
            };
            let file_type = metadata.file_type();
            let child_rel = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            let (kind, size) = if file_type.is_symlink() {
                ("link", None)
            } else if file_type.is_dir() {
                ("dir", None)
            } else if file_type.is_file() {
                ("file", Some(metadata.len() as i64))
            } else {
                ("other", None)
            };
            nodes.push(json!({
                "path": child_rel,
                "kind": kind,
                "size": size,
                "mtime": mtime_secs(&metadata),
                "mode": mode_string(&metadata),
            }));
            if kind == "dir" {
                if PRUNE_DIRS.contains(&name.as_str()) {
                    // Se lista la carpeta pero no se desciende: es ruido.
                } else if depth + 1 >= MAX_DEPTH {
                    truncated = true;
                } else {
                    stack.push((entry.path(), child_rel, depth + 1));
                }
            }
        }
        if nodes.len() >= MAX_NODES {
            truncated = true;
            break;
        }
    }
    nodes.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    (nodes, truncated)
}

/// Diff entre dos snapshots: altas, bajas y cambios (tamaño/fecha/permisos/
/// tipo) por ruta. Es un indicio para verificación humana, no un veredicto.
pub fn diff_nodes(previous: &[Value], current: &[Value]) -> Value {
    use std::collections::HashMap;
    let prev: HashMap<&str, &Value> = previous
        .iter()
        .filter_map(|n| n["path"].as_str().map(|p| (p, n)))
        .collect();
    let curr: HashMap<&str, &Value> = current
        .iter()
        .filter_map(|n| n["path"].as_str().map(|p| (p, n)))
        .collect();
    let mut added: Vec<Value> = Vec::new();
    let mut removed: Vec<Value> = Vec::new();
    let mut changed: Vec<Value> = Vec::new();
    for (path, node) in &curr {
        match prev.get(path) {
            None => added.push(json!({"path": path, "kind": node["kind"]})),
            Some(old) => {
                if old["kind"] != node["kind"]
                    || old["size"] != node["size"]
                    || old["mtime"] != node["mtime"]
                    || old["mode"] != node["mode"]
                {
                    changed.push(json!({
                        "path": path,
                        "kind": node["kind"],
                        "from": {"size": old["size"], "mtime": old["mtime"], "mode": old["mode"]},
                        "to": {"size": node["size"], "mtime": node["mtime"], "mode": node["mode"]},
                    }));
                }
            }
        }
    }
    for path in prev.keys() {
        if !curr.contains_key(path) {
            removed.push(json!({"path": path}));
        }
    }
    let by_path = |a: &Value, b: &Value| a["path"].as_str().cmp(&b["path"].as_str());
    added.sort_by(by_path);
    removed.sort_by(by_path);
    changed.sort_by(by_path);
    json!({"added": added, "removed": removed, "changed": changed})
}

fn resolve_root(app: &App, root_alias: &str) -> PathBuf {
    match root_alias {
        "external" => PathBuf::from("/data/external"),
        _ => PathBuf::from(&app.config.log_root),
    }
}

async fn previous_nodes(
    app: &App,
    service_id: Uuid,
    root_alias: &str,
    directory: &str,
    before: Option<Uuid>,
) -> Vec<Value> {
    let row = if let Some(before) = before {
        sqlx::query(
            "SELECT nodes FROM structure_snapshots WHERE service_id=$1 AND root_alias=$2 AND directory=$3 AND id<>$4 ORDER BY created_at DESC, id DESC LIMIT 1",
        )
        .bind(service_id)
        .bind(root_alias)
        .bind(directory)
        .bind(before)
        .fetch_optional(&app.pool)
        .await
    } else {
        sqlx::query(
            "SELECT nodes FROM structure_snapshots WHERE service_id=$1 AND root_alias=$2 AND directory=$3 ORDER BY created_at DESC, id DESC LIMIT 1",
        )
        .bind(service_id)
        .bind(root_alias)
        .bind(directory)
        .fetch_optional(&app.pool)
        .await
    };
    row.ok()
        .flatten()
        .and_then(|r| r.get::<Value, _>("nodes").as_array().cloned())
        .unwrap_or_default()
}

fn snapshot_json(row: &sqlx::postgres::PgRow, diff: Value) -> Value {
    json!({
        "id": row.get::<Uuid, _>("id"),
        "root_alias": row.get::<String, _>("root_alias"),
        "directory": row.get::<String, _>("directory"),
        "node_count": row.get::<i32, _>("node_count"),
        "truncated": row.get::<bool, _>("truncated"),
        "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
        "nodes": row.get::<Value, _>("nodes"),
        "diff": diff,
    })
}

/// Captura explícita del operador: escanea solo metadatos bajo la raíz
/// allowlisted + directorio validado y guarda el snapshot con su diff.
pub async fn capture(app: &App, service_id: Uuid, v: &Value) -> Result<Value> {
    let root_alias = v["root_alias"].as_str().ok_or_else(invalid)?;
    if !["demo-logs", "external"].contains(&root_alias) {
        return Err(invalid());
    }
    let directory = v["directory"].as_str().unwrap_or("");
    if !valid_directory(directory) {
        return Err(invalid());
    }
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM services WHERE id=$1 AND deleted_at IS NULL)",
    )
    .bind(service_id)
    .fetch_one(&app.pool)
    .await
    .map_err(|_| invalid())?;
    if !exists {
        return Err(not_found());
    }
    let root = resolve_root(app, root_alias);
    let base = if directory.is_empty() {
        root.clone()
    } else {
        root.join(directory)
    };
    let metadata = std::fs::symlink_metadata(&base).map_err(|_| invalid())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid());
    }
    if root_alias == "external" {
        // La raíz externa debe estar montada de solo lectura, igual que
        // exigen las fuentes de carpeta (collector::require_read_only).
        let file = std::fs::File::open(&base).map_err(|_| invalid())?;
        crate::collector::require_read_only(&file)
            .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "external_mount_not_read_only"))?;
    }
    let previous = previous_nodes(app, service_id, root_alias, directory, None).await;
    let (nodes, truncated) = scan_tree(&base);
    let mut diff = diff_nodes(&previous, &nodes);
    annotate_diff(app, service_id, root_alias, directory, &mut diff).await;
    let id = Uuid::new_v4();
    let row = sqlx::query(
        "INSERT INTO structure_snapshots(id,service_id,root_alias,directory,node_count,truncated,nodes,diff) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *",
    )
    .bind(id)
    .bind(service_id)
    .bind(root_alias)
    .bind(directory)
    .bind(nodes.len() as i32)
    .bind(truncated)
    .bind(json!(nodes))
    .bind(&diff)
    .fetch_one(&app.pool)
    .await
    .map_err(|_| invalid())?;
    evaluate_structure_incidents(app, service_id, root_alias, directory, &diff).await;
    Ok(snapshot_json(&row, diff))
}

/// Anota las rutas nuevas del diff con su clasificación de observabilidad
/// (OBS-01) y crea la incidencia agrupada correspondiente cuando el servicio
/// ya tiene eventos (run al que anclarla). La clasificación queda en el diff
/// devuelto y en el contexto que recibe la IA; no afirma compromiso.
async fn annotate_diff(
    app: &App,
    service_id: Uuid,
    root_alias: &str,
    directory: &str,
    diff: &mut Value,
) {
    let zones = observability::active_entries(&app.pool, service_id, Some("filesystem"))
        .await
        .unwrap_or_default();
    let zone_tuples: Vec<(Uuid, i32, Value)> = zones
        .iter()
        .map(|(id, rev, cfg, _)| (*id, *rev, cfg.clone()))
        .collect();
    let added_paths: Vec<String> = diff["added"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|n| n["path"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if added_paths.is_empty() {
        return;
    }
    let classified =
        observability::classify_structure_added(root_alias, directory, &added_paths, &zone_tuples);
    if let Some(items) = diff["added"].as_array_mut() {
        for (item, (_, kind, entry)) in items.iter_mut().zip(classified.iter()) {
            item["classification"] = json!(kind);
            item["matched_entry_id"] = json!(entry);
        }
    }
}

/// Semántica cerrada de las plantillas de estructura (seguimiento
/// REVIEW-OBS-01): se cuentan **rutas nuevas** clasificadas bajo la
/// plantilla en las capturas del mismo grupo (servicio + raíz + directorio)
/// dentro de `window_seconds`; al alcanzar `threshold` se abre la
/// incidencia del grupo y, mientras su último match siga dentro de la
/// ventana, las capturas siguientes la refrescan en vez de duplicarla
/// (anti-duplicación). `severity` es la severidad inicial. Sin DSL.
#[derive(Debug, Clone, PartialEq)]
pub struct StructureRule {
    pub enabled: bool,
    pub threshold: i64,
    pub window_seconds: i64,
    pub severity: String,
}

pub fn structure_rule(override_rule: Option<&Value>, template: &str) -> StructureRule {
    let (_, _, dt, dw, ds) = observability::TEMPLATES
        .iter()
        .find(|(id, _, _, _, _)| *id == template)
        .copied()
        .unwrap_or(("?", "?", 1, 300, "medium"));
    let pick_i64 = |key: &str, default: i64, range: std::ops::RangeInclusive<i64>| {
        override_rule
            .and_then(|r| r[key].as_i64())
            .filter(|n| range.contains(n))
            .unwrap_or(default)
    };
    StructureRule {
        enabled: !override_rule.is_some_and(|r| r["enabled"] == false),
        threshold: pick_i64("threshold", dt, 1..=100),
        window_seconds: pick_i64("window_seconds", dw, 1..=600),
        severity: override_rule
            .and_then(|r| r["severity"].as_str())
            .filter(|sev| ["low", "medium", "high", "critical"].contains(sev))
            .unwrap_or(ds)
            .to_string(),
    }
}

/// Rutas nuevas de un diff ya clasificado que caen bajo una plantilla.
pub fn count_classified(diff: &Value, template: &str) -> usize {
    diff["added"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter(|n| n["classification"] == template)
                .count()
        })
        .unwrap_or(0)
}

/// Suma los conteos de las capturas dentro de la ventana [now-window, now].
pub fn accumulated_within(captures: &[(i64, usize)], now: i64, window_seconds: i64) -> usize {
    captures
        .iter()
        .filter(|(t, _)| *t >= now - window_seconds && *t <= now)
        .map(|(_, n)| n)
        .sum()
}

#[derive(Debug, PartialEq)]
pub enum StructureAction {
    Create,
    Refresh,
    Skip,
}

pub fn structure_action(
    existing_open: bool,
    accumulated: usize,
    threshold: i64,
) -> StructureAction {
    if existing_open {
        StructureAction::Refresh
    } else if accumulated >= threshold.max(1) as usize {
        StructureAction::Create
    } else {
        StructureAction::Skip
    }
}

/// Evalúa las plantillas de estructura contra la captura recién persistida:
/// aplica enabled/threshold/window/severity de la regla del operador (o los
/// valores de la plantilla) y crea o refresca la incidencia agrupada cuando
/// el servicio ya tiene eventos (run al que anclarla).
async fn evaluate_structure_incidents(
    app: &App,
    service_id: Uuid,
    root_alias: &str,
    directory: &str,
    diff: &Value,
) {
    let now = chrono::Utc::now();
    for template in ["unexpected_structure_change", "sensitive_structure_change"] {
        let paths: Vec<String> = diff["added"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter(|n| n["classification"] == template)
                    .filter_map(|n| n["path"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        if paths.is_empty() {
            continue;
        }
        // Override del operador: la primera fuente de carpeta del servicio
        // que declare la plantilla (las raíces del mapa son de carpeta).
        let override_rule: Option<Value> = sqlx::query_scalar::<_, Value>(
            "SELECT analysis FROM sources WHERE service_id=$1 AND kind='folder' AND deleted_at IS NULL ORDER BY id",
        )
        .bind(service_id)
        .fetch_all(&app.pool)
        .await
        .unwrap_or_default()
        .iter()
        .find_map(|a| {
            a["rules"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|r| r["id"] == template)
                .cloned()
        });
        let rule = structure_rule(override_rule.as_ref(), template);
        if !rule.enabled {
            continue;
        }
        let run: Option<Uuid> = sqlx::query_scalar(
            "SELECT run_id FROM events WHERE service_id=$1 ORDER BY ingest_seq DESC LIMIT 1",
        )
        .bind(service_id)
        .fetch_optional(&app.pool)
        .await
        .ok()
        .flatten();
        let Some(run) = run else { continue };
        let group = json!({"service_id":service_id,"classification":template,"root_alias":root_alias,"directory":directory});
        let definition = json!({"template":template,"kind":"observability","version":1});
        let _ = sqlx::query("INSERT INTO rule_versions VALUES($1,1,$2,$3) ON CONFLICT DO NOTHING")
            .bind(template)
            .bind(&definition)
            .bind(hash(definition.to_string()))
            .execute(&app.pool)
            .await;
        let window_start = now - chrono::Duration::seconds(rule.window_seconds);
        // Acumulación: diffs persistidos del grupo dentro de la ventana
        // (la captura actual ya está insertada y cuenta).
        let recent: Vec<(i64, usize)> = sqlx::query(
            "SELECT diff, created_at FROM structure_snapshots WHERE service_id=$1 AND root_alias=$2 AND directory=$3 AND created_at >= $4",
        )
        .bind(service_id)
        .bind(root_alias)
        .bind(directory)
        .bind(window_start)
        .fetch_all(&app.pool)
        .await
        .unwrap_or_default()
        .iter()
        .map(|r| {
            (
                r.get::<chrono::DateTime<chrono::Utc>, _>("created_at").timestamp(),
                count_classified(&r.get::<Value, _>("diff"), template),
            )
        })
        .collect();
        let accumulated = accumulated_within(&recent, now.timestamp(), rule.window_seconds);
        // Anti-duplicación por el grupo semántico aprobado (servicio +
        // plantilla + raíz + directorio, ya codificado en group_key) y la
        // ventana: run_id NO forma parte del criterio (seguimiento FIX2).
        // El run solo ancla la primera incidencia al crearla.
        let existing: Option<(Uuid, Value)> = sqlx::query(
            "SELECT id, deterministic_reason FROM incidents WHERE rule_id=$1 AND group_key=$2 AND last_match_at >= $3 ORDER BY opened_at DESC LIMIT 1",
        )
        .bind(template)
        .bind(&group)
        .bind(window_start)
        .fetch_optional(&app.pool)
        .await
        .ok()
        .flatten()
        .map(|r| (r.get::<Uuid, _>("id"), r.get::<Value, _>("deterministic_reason")));
        let title = if template == "sensitive_structure_change" {
            "Cambio en zona sensible de la estructura"
        } else {
            "Cambio de estructura no esperado"
        };
        match structure_action(existing.is_some(), accumulated, rule.threshold) {
            StructureAction::Skip => {}
            StructureAction::Refresh => {
                let (existing_id, mut reason) = existing.unwrap();
                let mut merged: Vec<String> = reason["added_paths"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|p| p.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                for p in &paths {
                    if !merged.contains(p) {
                        merged.push(p.clone());
                    }
                }
                merged.truncate(10);
                reason["added_paths"] = json!(merged);
                reason["accumulated_paths"] = json!(accumulated);
                reason["threshold"] = json!(rule.threshold);
                reason["window_seconds"] = json!(rule.window_seconds);
                let _ = sqlx::query(
                    "UPDATE incidents SET last_match_at=$2, deterministic_reason=$3 WHERE id=$1",
                )
                .bind(existing_id)
                .bind(now)
                .bind(&reason)
                .execute(&app.pool)
                .await;
            }
            StructureAction::Create => {
                let reason = json!({"template":template,"root_alias":root_alias,"directory":directory,"added_paths":paths.iter().take(10).collect::<Vec<_>>(),"threshold":rule.threshold,"window_seconds":rule.window_seconds,"accumulated_paths":accumulated,"note":"señal determinista sobre metadatos: un archivo nuevo no confirma webshell ni compromiso; requiere verificación humana"});
                let id = Uuid::new_v4();
                if sqlx::query("INSERT INTO incidents(id,incident_key,run_id,rule_id,rule_version,group_key,severity,title,opened_at,last_match_at,deterministic_reason,pending_since,eligible_at) VALUES($1,$2,$3,$4,1,$5,$6,$7,$8,$8,$9,$8,$8)")
                    .bind(id).bind(hash(format!("{template}:1:{run}:{group}:{now}"))).bind(run).bind(template).bind(&group).bind(&rule.severity).bind(title).bind(now).bind(reason).execute(&app.pool).await.is_ok()
                {
                    let _ = sqlx::query("INSERT INTO incident_services(incident_id,service_id) VALUES($1,$2) ON CONFLICT DO NOTHING")
                        .bind(id).bind(service_id).execute(&app.pool).await;
                    if let Ok(mut tx) = app.pool.begin().await {
                        let _ = db::emit(&mut tx, "report.created", id, 1).await;
                        let _ = tx.commit().await;
                    }
                }
            }
        }
    }
}

/// Último snapshot por raíz+directorio, con su diff, más el historial.
pub async fn overview(app: &App, service_id: Uuid) -> Result<Value> {
    let rows = sqlx::query(
        "SELECT * FROM structure_snapshots WHERE service_id=$1 ORDER BY created_at DESC, id DESC LIMIT 50",
    )
    .bind(service_id)
    .fetch_all(&app.pool)
    .await
    .map_err(|_| invalid())?;
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    let mut latest: Vec<Value> = Vec::new();
    let mut previous_by_root: std::collections::HashMap<(String, String), Vec<Value>> =
        std::collections::HashMap::new();
    for row in &rows {
        let key = (
            row.get::<String, _>("root_alias"),
            row.get::<String, _>("directory"),
        );
        if seen.insert(key.clone()) {
            // Trazabilidad (seguimiento FIX2): si la captura persistió su
            // diff clasificado (migración 0030), se devuelve tal cual, con
            // classification/matched_entry_id. Los históricos con diff {}
            // se marcan "recomputed" y se recalculan desde nodes, sin
            // reinterpretar clasificaciones que nunca se guardaron.
            let persisted = row.get::<Value, _>("diff");
            let has_persisted = persisted.get("added").is_some_and(|a| a.is_array());
            let mut item = snapshot_json(
                row,
                if has_persisted {
                    persisted
                } else {
                    Value::Null
                },
            );
            item["diff_source"] = json!(if has_persisted {
                "persisted"
            } else {
                "recomputed"
            });
            latest.push(item);
        } else {
            previous_by_root.entry(key).or_insert_with(|| {
                row.get::<Value, _>("nodes")
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
            });
        }
    }
    for item in latest.iter_mut() {
        let key = (
            item["root_alias"].as_str().unwrap_or("").to_owned(),
            item["directory"].as_str().unwrap_or("").to_owned(),
        );
        if item["diff_source"] == "recomputed" {
            let current = item["nodes"].as_array().cloned().unwrap_or_default();
            let previous = previous_by_root.get(&key).cloned().unwrap_or_default();
            item["diff"] = if previous_by_root.contains_key(&key) {
                diff_nodes(&previous, &current)
            } else {
                json!({"added": [], "removed": [], "changed": [], "first_capture": true})
            };
        }
    }
    let history: Vec<Value> = rows
        .iter()
        .take(10)
        .map(|row| {
            json!({
                "id": row.get::<Uuid, _>("id"),
                "root_alias": row.get::<String, _>("root_alias"),
                "directory": row.get::<String, _>("directory"),
                "node_count": row.get::<i32, _>("node_count"),
                "truncated": row.get::<bool, _>("truncated"),
                "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
            })
        })
        .collect();
    Ok(json!({"roots": latest, "history": history}))
}

/// Contexto de estructura para el snapshot del gateway: por servicio, las
/// raíces mapeadas y el último diff acotado. Solo entra si hay capturas.
pub async fn context_for_services(app: &App, service_ids: &[Uuid]) -> Vec<Value> {
    let mut out = Vec::new();
    for id in service_ids {
        let Ok(overview) = overview(app, *id).await else {
            continue;
        };
        let Some(roots) = overview["roots"].as_array() else {
            continue;
        };
        if roots.is_empty() {
            continue;
        }
        let name: Option<String> = sqlx::query_scalar("SELECT name FROM services WHERE id=$1")
            .bind(id)
            .fetch_optional(&app.pool)
            .await
            .ok()
            .flatten();
        let summaries: Vec<Value> = roots
            .iter()
            .map(|root| {
                let cap = |list: &Value| {
                    list.as_array()
                        .map(|a| a.iter().take(10).cloned().collect::<Vec<_>>())
                        .unwrap_or_default()
                };
                json!({
                    "root_alias": root["root_alias"],
                    "directory": root["directory"],
                    "node_count": root["node_count"],
                    "truncated": root["truncated"],
                    "captured_at": root["created_at"],
                    "diff_added": cap(&root["diff"]["added"]),
                    "diff_removed": cap(&root["diff"]["removed"]),
                    "diff_changed": cap(&root["diff"]["changed"]),
                })
            })
            .collect();
        out.push(json!({"service_id": id, "name": name, "roots": summaries}));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(path: &str, kind: &str, size: Option<i64>, mtime: i64) -> Value {
        json!({"path": path, "kind": kind, "size": size, "mtime": mtime, "mode": "0644"})
    }

    #[test]
    fn structure_rule_semantics_threshold_window_severity() {
        // Sin override: valores de la plantilla (umbral 1, ventana 300)
        let rule = structure_rule(None, "unexpected_structure_change");
        assert!(rule.enabled);
        assert_eq!(rule.threshold, 1);
        assert_eq!(rule.window_seconds, 300);
        assert_eq!(rule.severity, "medium");
        let rule = structure_rule(None, "sensitive_structure_change");
        assert_eq!(rule.severity, "high");
        // Override completo del operador
        let ov = json!({"id":"unexpected_structure_change","enabled":true,"threshold":5,"window_seconds":60,"severity":"critical"});
        let rule = structure_rule(Some(&ov), "unexpected_structure_change");
        assert_eq!(rule.threshold, 5);
        assert_eq!(rule.window_seconds, 60);
        assert_eq!(rule.severity, "critical");
        // Valores fuera del modelo cerrado caen al valor de la plantilla
        let bad = json!({"id":"unexpected_structure_change","enabled":true,"threshold":0,"window_seconds":9999,"severity":"urgent"});
        let rule = structure_rule(Some(&bad), "unexpected_structure_change");
        assert_eq!(rule.threshold, 1);
        assert_eq!(rule.window_seconds, 300);
        assert_eq!(rule.severity, "medium");
        // Regla desactivada
        let off = json!({"id":"sensitive_structure_change","enabled":false,"threshold":1,"window_seconds":300,"severity":"high"});
        assert!(!structure_rule(Some(&off), "sensitive_structure_change").enabled);
    }

    #[test]
    fn structure_counting_and_window() {
        let diff = json!({"added":[
            {"path":"a.php","classification":"sensitive_structure_change"},
            {"path":"b.txt","classification":"unexpected_structure_change"},
            {"path":"c.php","classification":"sensitive_structure_change"},
            {"path":"d.txt"}
        ]});
        assert_eq!(count_classified(&diff, "sensitive_structure_change"), 2);
        assert_eq!(count_classified(&diff, "unexpected_structure_change"), 1);
        // La ventana excluye capturas viejas y futuras
        let now = 10_000;
        let captures = vec![(now - 301, 5usize), (now - 299, 2), (now, 1), (now + 5, 7)];
        assert_eq!(accumulated_within(&captures, now, 300), 3);
        assert_eq!(accumulated_within(&captures, now, 60), 1);
    }

    #[test]
    fn structure_action_threshold_and_antiduplication() {
        // Bajo el umbral no se abre nada
        assert_eq!(structure_action(false, 2, 3), StructureAction::Skip);
        // Al alcanzar el umbral acumulado se abre
        assert_eq!(structure_action(false, 3, 3), StructureAction::Create);
        assert_eq!(structure_action(false, 4, 3), StructureAction::Create);
        // Con una incidencia del grupo abierta en la ventana, se refresca:
        // nunca se duplica aunque el acumulado por sí solo no llegue
        assert_eq!(structure_action(true, 1, 3), StructureAction::Refresh);
        assert_eq!(structure_action(true, 9, 3), StructureAction::Refresh);
    }

    #[test]
    fn scan_lists_metadata_without_opening_and_skips_sensitive_names() {
        let dir = std::env::temp_dir().join(format!("structure-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("uploads")).unwrap();
        std::fs::write(dir.join("index.php"), b"<?php").unwrap();
        std::fs::write(dir.join("uploads/shell.php"), b"x").unwrap();
        std::fs::write(dir.join(".env"), b"SECRET=1").unwrap();
        std::fs::write(dir.join("api.key"), b"k").unwrap();
        let (nodes, truncated) = scan_tree(&dir);
        assert!(!truncated);
        let paths: Vec<&str> = nodes.iter().filter_map(|n| n["path"].as_str()).collect();
        assert!(paths.contains(&"index.php"));
        assert!(paths.contains(&"uploads"));
        assert!(paths.contains(&"uploads/shell.php"));
        assert!(
            !paths
                .iter()
                .any(|p| p.contains(".env") || p.contains(".key"))
        );
        let file = nodes.iter().find(|n| n["path"] == "index.php").unwrap();
        assert_eq!(file["kind"], "file");
        assert_eq!(file["size"], 5);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn diff_reports_added_removed_and_changed() {
        let prev = vec![
            node("a.txt", "file", Some(3), 100),
            node("gone.txt", "file", Some(1), 100),
            node("same.txt", "file", Some(2), 100),
        ];
        let curr = vec![
            node("a.txt", "file", Some(9), 200),
            node("new.php", "file", Some(1), 200),
            node("same.txt", "file", Some(2), 100),
        ];
        let diff = diff_nodes(&prev, &curr);
        assert_eq!(diff["added"][0]["path"], "new.php");
        assert_eq!(diff["removed"][0]["path"], "gone.txt");
        assert_eq!(diff["changed"][0]["path"], "a.txt");
        assert_eq!(diff["changed"][0]["from"]["size"], 3);
        assert_eq!(diff["changed"][0]["to"]["size"], 9);
    }

    #[test]
    fn excluded_names_cover_secrets_and_keys() {
        assert!(excluded_name(".env"));
        assert!(excluded_name("db-secret.txt"));
        assert!(excluded_name("server.key"));
        assert!(excluded_name("id_rsa"));
        assert!(!excluded_name("index.php"));
        assert!(!excluded_name("access.log"));
    }
}
