use crate::contracts::*;
use crate::*;
use sqlx::Row;
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read, Seek, SeekFrom},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};
use uuid::Uuid;
pub fn require_read_only(file: &File) -> anyhow::Result<()> {
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::fstatvfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    anyhow::ensure!(
        unsafe { stat.assume_init() }.f_flag & libc::ST_RDONLY != 0,
        "external_mount_not_read_only"
    );
    Ok(())
}
/// Open a single configured directory beneath the allowed root, never through a symlink.
pub fn safe_directory(root: &Path, directory: &str) -> anyhow::Result<File> {
    anyhow::ensure!(
        directory.is_empty()
            || (directory.len() <= 64
                && directory
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))),
        "directory_denied"
    );
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)?;
    if directory.is_empty() {
        return Ok(root);
    }
    open_at(&root, std::ffi::OsStr::new(directory), libc::O_DIRECTORY)
}
fn open_at(parent: &File, name: &std::ffi::OsStr, flags: i32) -> anyhow::Result<File> {
    let name = std::ffi::CString::new(name.as_encoded_bytes())?;
    let before = if flags == 0 {
        let mut before = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                before.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let before = unsafe { before.assume_init() };
        anyhow::ensure!(
            before.st_mode & libc::S_IFMT == libc::S_IFREG,
            "not_regular_file"
        );
        Some(before)
    } else {
        None
    };
    // The directory descriptor anchors lookup even if its pathname is replaced concurrently.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC | flags,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    if let Some(before) = before {
        let after = file.metadata()?;
        anyhow::ensure!(
            after.is_file() && after.dev() == before.st_dev && after.ino() == before.st_ino,
            "identity_changed"
        );
    }
    Ok(file)
}
pub fn safe_regular(path: &Path, root: &Path) -> anyhow::Result<File> {
    use std::path::Component;
    let relative = path.strip_prefix(root)?;
    let parts = relative.components().collect::<Vec<_>>();
    anyhow::ensure!(
        (1..=2).contains(&parts.len()) && parts.iter().all(|c| matches!(c, Component::Normal(_))),
        "path_denied"
    );
    let directory = if parts.len() == 2 {
        parts[0]
            .as_os_str()
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("directory_denied"))?
    } else {
        ""
    };
    let parent = safe_directory(root, directory)?;
    let file = open_at(&parent, parts.last().unwrap().as_os_str(), 0)?;
    anyhow::ensure!(file.metadata()?.is_file(), "not_regular_file");
    Ok(file)
}
pub fn safe_open(path: &Path, root: &Path) -> anyhow::Result<File> {
    anyhow::ensure!(
        path.extension()
            .is_some_and(|s| matches!(s.to_str(), Some("ndjson" | "log"))),
        "path_denied"
    );
    safe_regular(path, root)
}
pub fn selector_matches(selector: &str, name: &str) -> bool {
    match selector.split_once('*') {
        Some((a, b)) => name.starts_with(a) && name.ends_with(b) && name.len() >= a.len() + b.len(),
        None => selector == name,
    }
}
pub async fn poll(app: &App) -> anyhow::Result<()> {
    let sources = sqlx::query("SELECT x.id,x.service_id,x.version,x.capture_version,x.config,x.data_class,s.name FROM sources x JOIN services s ON s.id=x.service_id WHERE x.kind='folder' AND x.enabled AND x.deleted_at IS NULL AND s.enabled AND s.deleted_at IS NULL ORDER BY x.updated_at,x.id")
        .fetch_all(&app.pool).await?;
    for source in &sources {
        let source_id: Uuid = source.get("id");
        let service_id: Uuid = source.get("service_id");
        let source_version: i32 = source.get("version");
        let capture_version: i32 = source.get("capture_version");
        let config: serde_json::Value = source.get("config");
        let real = source.get::<String, _>("data_class") == "real";
        let alias = config["root_alias"].as_str().unwrap_or("");
        if (real && (alias != "external" || config["data_class"] != "real"))
            || (!real && alias != "demo-logs")
            || services::validate_config("folder", &config).is_err()
        {
            source_error(app, source_id, "invalid_source_configuration").await?;
            continue;
        }
        let root = if real {
            Path::new("/data/external")
        } else {
            Path::new(&app.config.log_root)
        };
        let directory = config["directory"].as_str().unwrap_or("");
        let handle = match safe_directory(root, directory) {
            Ok(h) => h,
            Err(_) => {
                source_error(app, source_id, "unsafe_source_directory").await?;
                continue;
            }
        };
        if real && require_read_only(&handle).is_err() {
            source_error(app, source_id, "external_mount_not_read_only").await?;
            continue;
        }
        let mut paths = std::fs::read_dir(format!("/proc/self/fd/{}", handle.as_raw_fd()))?
            .filter_map(Result::ok)
            .map(|entry| root.join(directory).join(entry.file_name()))
            .filter(|path| {
                path.extension()
                    .is_some_and(|s| matches!(s.to_str(), Some("ndjson" | "log")))
            })
            .collect::<Vec<_>>();
        paths.sort();
        let selector = config["selector"].as_str().unwrap_or("");
        let stored: i64 =
            sqlx::query_scalar(if real {"SELECT real_queue_bytes()"} else {"SELECT coalesce(sum(byte_length),0)::bigint FROM text_records WHERE data_class='synthetic'"})
                .fetch_one(&app.pool)
                .await?;
        if stored >= 268435456 {
            source_error(app, source_id, "record_storage_backpressure").await?;
            break;
        }
        let mut seen = Vec::new();
        for path in &paths {
            let name = path.file_name().unwrap().to_string_lossy();
            if !selector_matches(selector, &name) {
                continue;
            }
            let overlap = sources
                .iter()
                .filter(|other| {
                    let c: serde_json::Value = other.get("config");
                    c["root_alias"] == config["root_alias"]
                        && c["directory"].as_str().unwrap_or("") == directory
                        && selector_matches(c["selector"].as_str().unwrap_or(""), &name)
                })
                .count()
                > 1;
            if overlap {
                source_error(app, source_id, "ambiguous_source_selector").await?;
                continue;
            }
            let pending: i64 =
                sqlx::query_scalar("SELECT count(*) FROM detection_work WHERE state='pending'")
                    .fetch_one(&app.pool)
                    .await?;
            if pending >= 2000 {
                break;
            }
            let file = match safe_open(path, root) {
                Ok(f) => f,
                Err(_) => {
                    source_error(app, source_id, "unsafe_file").await?;
                    continue;
                }
            };
            if real && require_read_only(&file).is_err() {
                source_error(app, source_id, "external_mount_not_read_only").await?;
                continue;
            }
            let meta = file.metadata()?;
            let dev = meta.dev() as i64;
            let ino = meta.ino() as i64;
            seen.push((dev, ino));
            if !real && meta.len() > 104857600 {
                source_error(app, source_id, "file_too_large").await?;
                continue;
            }
            ingest_file(
                app,
                file,
                dev,
                ino,
                path.strip_prefix(root)?
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("invalid_source_path"))?,
                ((2000 - pending) as usize).min(200),
                source_id,
                service_id,
                source_version,
                capture_version,
                &source.get::<String, _>("name"),
                root,
                real,
                config["year"].as_i64().unwrap_or(0) as i32,
            )
            .await?;
        }
        let old = sqlx::query(
            "SELECT id,device,inode FROM file_instances WHERE retired_at IS NULL AND source_id=$1",
        )
        .bind(source_id)
        .fetch_all(&app.pool)
        .await?;
        for r in old {
            if !seen.contains(&(r.get("device"), r.get("inode")))
                && !paths.iter().any(|path| {
                    selector_matches(selector, &path.file_name().unwrap().to_string_lossy())
                        && safe_open(path, root)
                            .and_then(|f| Ok(f.metadata()?))
                            .is_ok_and(|m| {
                                m.is_file()
                                    && m.dev() as i64 == r.get::<i64, _>("device")
                                    && m.ino() as i64 == r.get::<i64, _>("inode")
                            })
                })
            {
                sqlx::query("UPDATE file_instances SET retired_at=now() WHERE id=$1")
                    .bind(r.get::<Uuid, _>("id"))
                    .execute(&app.pool)
                    .await?;
                source_error(app, source_id, "source_gap").await?;
            }
        }
    }
    Ok(())
}
async fn source_error(app: &App, source_id: Uuid, code: &str) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE sources SET status='degraded',last_error_code=$1,updated_at=now() WHERE id=$2",
    )
    .bind(code)
    .bind(source_id)
    .execute(&app.pool)
    .await?;
    Ok(())
}
#[allow(clippy::too_many_arguments)]
async fn ingest_file(
    app: &App,
    mut file: File,
    dev: i64,
    ino: i64,
    name: &str,
    batch_limit: usize,
    source_id: Uuid,
    service_id: Uuid,
    source_version: i32,
    capture_version: i32,
    service_name: &str,
    root: &Path,
    real: bool,
    source_year: i32,
) -> anyhow::Result<()> {
    let size = file.metadata()?.len() as i64;
    let mut native = if name.ends_with(".log") {
        if real {
            Some(log_formats::NativeSource {
                schema_version: 1,
                synthetic: false,
                run_id: Uuid::new_v5(&source_id, b"real-log-source"),
                sha256: String::new(),
                year: source_year,
                timezone: "UTC".into(),
            })
        } else {
            match log_formats::source_in_root(&root.join(name), root) {
                Ok(source)
                    if size <= 104857600 && log_formats::verify(&mut file, &source).is_ok() =>
                {
                    Some(source)
                }
                _ => {
                    source_error(app, source_id, "native_source_unverified").await?;
                    return Ok(());
                }
            }
        }
    } else {
        None
    };
    let old=sqlx::query("SELECT f.*,c.committed_offset FROM file_instances f JOIN source_cursors c ON c.file_instance_id=f.id WHERE f.source_id=$1 AND device=$2 AND inode=$3 AND capture_version=$4 ORDER BY generation DESC LIMIT 1").bind(source_id).bind(dev).bind(ino).bind(capture_version).fetch_optional(&app.pool).await?;
    let (id, generation, offset, prefix_len, prefix_hash, discontinuity) = if let Some(r) = old {
        let n: i32 = r.get("prefix_len");
        let mut prefix = vec![0; n as usize];
        let got = file.read(&mut prefix)?;
        let changed = got != n as usize
            || hash(&prefix) != r.get::<String, _>("prefix_hash")
            || size < r.get("committed_offset");
        if changed {
            (
                Uuid::new_v4(),
                r.get::<i32, _>("generation") + 1,
                0_i64,
                0_i32,
                String::new(),
                true,
            )
        } else {
            (
                r.get("id"),
                r.get("generation"),
                r.get("committed_offset"),
                n,
                r.get("prefix_hash"),
                false,
            )
        }
    } else {
        (Uuid::new_v4(), 0, 0_i64, 0_i32, String::new(), false)
    };
    if real && let Some(source) = native.as_mut() {
        source.sha256 = format!("{source_id}:{dev}:{ino}:{capture_version}:{generation}");
    }
    file.seek(SeekFrom::Start(0))?;
    let n = if prefix_len == 0 {
        size.min(4096) as usize
    } else {
        prefix_len as usize
    };
    let mut prefix = vec![0; n];
    file.read_exact(&mut prefix)?;
    let ph = if prefix_len == 0 || prefix_hash.is_empty() {
        hash(&prefix)
    } else {
        prefix_hash
    };
    let preserved: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM record_locations l JOIN text_records r ON r.id=l.record_id WHERE l.file_instance_id=$1 AND (r.original IS NOT NULL OR r.local_reason='record_exceeds_1mib_reference_only'))",
    )
    .bind(id)
    .fetch_one(&app.pool)
    .await?;
    let offset = if !real && offset > 0 && !preserved {
        0
    } else {
        offset
    };
    file.seek(SeekFrom::Start(offset as u64))?;
    let mut reader = BufReader::with_capacity(8192, file);
    let mut tx = app.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(7616)")
        .execute(&mut *tx)
        .await?;
    let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sources x JOIN services s ON s.id=x.service_id WHERE x.id=$1 AND x.version=$2 AND x.data_class=$3 AND x.enabled AND x.deleted_at IS NULL AND s.enabled AND s.deleted_at IS NULL)").bind(source_id).bind(source_version).bind(if real {"real"} else {"synthetic"}).fetch_one(&mut *tx).await?;
    if !active {
        return Ok(());
    }
    let adapter: String =
        sqlx::query_scalar("SELECT analysis->>'adapter' FROM sources WHERE id=$1")
            .bind(source_id)
            .fetch_one(&mut *tx)
            .await?;
    sqlx::query("INSERT INTO file_instances(id,source_id,device,inode,generation,prefix_hash,prefix_len,current_path,capture_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(id) DO UPDATE SET current_path=$8,retired_at=NULL").bind(id).bind(source_id).bind(dev).bind(ino).bind(generation).bind(ph).bind(n as i32).bind(name).bind(capture_version).execute(&mut *tx).await?;
    if discontinuity {
        diagnostic(&mut tx, id, 0, 0, "source_discontinuity", "").await?;
    }
    let mut stored: i64 = sqlx::query_scalar(if real {
        "SELECT real_queue_bytes()"
    } else {
        "SELECT coalesce(sum(byte_length),0)::bigint FROM text_records WHERE data_class='synthetic'"
    })
    .fetch_one(&mut *tx)
    .await?;
    let mut end = offset;
    for _ in 0..batch_limit {
        let start = end;
        let mut line = Vec::new();
        let mut length = 0;
        let mut complete = false;
        let mut digest = sha2::Sha256::new();
        use sha2::Digest;
        loop {
            let b = reader.fill_buf()?;
            if b.is_empty() {
                break;
            }
            let pos = b.iter().position(|c| *c == b'\n');
            let take = pos.map_or(b.len(), |p| p + 1);
            length += take as i64;
            digest.update(&b[..take]);
            if line.len() + take <= 1048576 {
                line.extend_from_slice(&b[..take]);
            }
            reader.consume(take);
            if pos.is_some() {
                complete = true;
                break;
            }
        }
        if !complete {
            if length > 65536 {
                source_error(app, source_id, "oversized_partial_line").await?;
            }
            break;
        }
        if stored.saturating_add(if real {
            length.saturating_mul(4)
        } else {
            length
        }) > 268435456
        {
            sqlx::query("UPDATE sources SET status='degraded',last_error_code='record_storage_backpressure' WHERE id=$1").bind(source_id).execute(&mut *tx).await?;
            break;
        }
        stored += if real {
            length.saturating_mul(4)
        } else {
            length
        };
        end += length;
        let line_hash = hex::encode(digest.finalize());
        if length > 1048576 {
            crate::review::preserve(
                &mut tx,
                app,
                id,
                generation,
                start,
                end,
                &line_hash,
                None,
                native.as_ref(),
                None,
                source_id,
                service_id,
                service_name,
            )
            .await?;
            diagnostic(&mut tx, id, start, end, "line_too_large", &line_hash).await?;
            continue;
        }
        let parsed = match (adapter.as_str(), &native) {
            ("plain-text", _) | ("sentinel-json", Some(_)) | ("native-text", None) => {
                Err(anyhow::anyhow!("source_adapter_does_not_parse"))
            }
            (_, Some(source)) => log_formats::parse(&line, source, start),
            _ => parse_line_with_class(&line, real).map(|e| (e, "sentinel-json")),
        };
        crate::review::preserve(
            &mut tx,
            app,
            id,
            generation,
            start,
            end,
            &line_hash,
            Some(&line),
            native.as_ref(),
            parsed.as_ref().ok(),
            source_id,
            service_id,
            service_name,
        )
        .await?;
        match parsed {
            Ok((e, parser)) => {
                let internal = Uuid::new_v5(&e.scenario_run_id, e.event_id.as_bytes());
                sqlx::query("INSERT INTO demo_runs(id) VALUES($1) ON CONFLICT DO NOTHING")
                    .bind(e.scenario_run_id)
                    .execute(&mut *tx)
                    .await?;
                let existing: Option<String> = sqlx::query_scalar(
                    "SELECT line_hash FROM events WHERE run_id=$1 AND external_event_id=$2",
                )
                .bind(e.scenario_run_id)
                .bind(e.event_id)
                .fetch_optional(&mut *tx)
                .await?;
                if let Some(h) = existing {
                    let owner: Option<Uuid> = sqlx::query_scalar(
                        "SELECT service_id FROM events WHERE run_id=$1 AND external_event_id=$2",
                    )
                    .bind(e.scenario_run_id)
                    .bind(e.event_id)
                    .fetch_one(&mut *tx)
                    .await?;
                    anyhow::ensure!(owner == Some(service_id), "logical_service_conflict");
                    if h != line_hash {
                        diagnostic(&mut tx, id, start, end, "logical_hash_conflict", &line_hash)
                            .await?;
                    }
                    continue;
                }
                let seq:i64=sqlx::query_scalar("INSERT INTO events(id,run_id,external_event_id,source_id,file_instance_id,generation,byte_start,byte_end,line_hash,event_time,source,event_type,level,src_ip,user_alias,service,message,schema_version,http) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,1,$18) RETURNING ingest_seq")
 .bind(internal).bind(e.scenario_run_id).bind(e.event_id).bind(source_id).bind(id).bind(generation).bind(start).bind(end).bind(&line_hash).bind(e.timestamp).bind(&e.source).bind(e.event_type).bind(e.level).bind(e.src_ip).bind(e.user.map(|s|redact(&s,&app.config.session_id))).bind(service_name).bind(redact(&e.message,&app.config.session_id)).bind(&e.http).fetch_one(&mut *tx).await?;
                sqlx::query("INSERT INTO detection_work(event_id,ingest_seq) VALUES($1,$2)")
                    .bind(internal)
                    .bind(seq)
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("UPDATE events SET parser=$2,service_id=$3,data_class=$4 WHERE id=$1")
                    .bind(internal)
                    .bind(parser)
                    .bind(service_id)
                    .bind(if real { "real" } else { "synthetic" })
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("UPDATE text_records SET event_id=$1 WHERE id=$1")
                    .bind(internal)
                    .execute(&mut *tx)
                    .await?;
                if native.is_none() {
                    let raw: serde_json::Value = serde_json::from_slice(&line)?;
                    if raw.as_object().unwrap().keys().any(|k| {
                        ![
                            "schema_version",
                            "scenario_run_id",
                            "event_id",
                            "seq",
                            "timestamp",
                            "source",
                            "event_type",
                            "level",
                            "message",
                            "src_ip",
                            "user",
                            "service",
                            "request_id",
                        ]
                        .contains(&k.as_str())
                    }) {
                        diagnostic(
                            &mut tx,
                            id,
                            start,
                            end,
                            "unknown_fields_discarded",
                            &line_hash,
                        )
                        .await?;
                    }
                }
            }
            Err(_) => {
                diagnostic(
                    &mut tx,
                    id,
                    start,
                    end,
                    if native.is_some() {
                        "native_record_unsupported_or_invalid"
                    } else {
                        "invalid_log_schema"
                    },
                    &line_hash,
                )
                .await?
            }
        }
    }
    sqlx::query("INSERT INTO source_cursors(file_instance_id,committed_offset,last_size) VALUES($1,$2,$3) ON CONFLICT(file_instance_id) DO UPDATE SET committed_offset=$2,last_size=$3,updated_at=now()").bind(id).bind(end).bind(size).execute(&mut *tx).await?;
    if std::env::var("SENTINEL_FAILPOINT").as_deref() == Ok("ingest_before_commit") {
        std::process::abort();
    }
    sqlx::query("UPDATE sources SET status='healthy',last_error_code=NULL,updated_at=now() WHERE id=$1 AND last_error_code IS DISTINCT FROM 'record_storage_backpressure'").bind(source_id).execute(&mut *tx).await?;
    tx.commit().await?;
    if std::env::var("SENTINEL_FAILPOINT").as_deref() == Ok("ingest_after_commit") {
        std::process::abort();
    }
    Ok(())
}
async fn diagnostic(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    start: i64,
    end: i64,
    reason: &str,
    h: &str,
) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO ingestion_errors(source_id,file_instance_id,byte_start,byte_end,reason,content_hash) SELECT source_id,id,$2,$3,$4,$5 FROM file_instances WHERE id=$1 ON CONFLICT DO NOTHING").bind(id).bind(start).bind(end).bind(reason).bind(h).execute(&mut **tx).await?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn denies_unsafe() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a.ndjson");
        std::os::unix::fs::symlink("/etc/passwd", &p).unwrap();
        assert!(safe_open(&p, d.path()).is_err());
        assert!(safe_open(Path::new("/tmp/x.ndjson"), d.path()).is_err());
    }
}
#[cfg(test)]
mod race_tests {
    use super::*;
    #[test]
    fn fifo_and_symlink_swap_are_denied() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("synthetic-canary");
        std::fs::write(&secret, b"outside canary").unwrap();
        let fifo = root.path().join("pipe.ndjson");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(safe_open(&fifo, root.path()).is_err());
        let path = root.path().join("race.ndjson");
        std::fs::write(&path, b"synthetic safe").unwrap();
        let directory = root.path().to_path_buf();
        let worker_path = path.clone();
        let writer = std::thread::spawn(move || {
            for _ in 0..200 {
                let plain = directory.join("regular.tmp");
                std::fs::write(&plain, b"synthetic safe").unwrap();
                std::fs::rename(&plain, &worker_path).unwrap();
                let link = directory.join("link.tmp");
                std::os::unix::fs::symlink(&secret, &link).unwrap();
                std::fs::rename(&link, &worker_path).unwrap();
            }
        });
        for _ in 0..1000 {
            if let Ok(mut f) = safe_open(&path, root.path()) {
                let mut body = String::new();
                f.read_to_string(&mut body).unwrap();
                assert_eq!(body, "synthetic safe");
            }
        }
        writer.join().unwrap();
        assert!(safe_open(&path, root.path()).is_err());
    }
}

#[cfg(test)]
mod directory_tests {
    use super::*;
    #[test]
    fn one_level_directory_and_sidecar_are_anchored() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("nginx")).unwrap();
        let log = root.path().join("nginx/access.log");
        std::fs::write(&log, b"synthetic log").unwrap();
        let mut file = safe_open(&log, root.path()).unwrap();
        let mut value = String::new();
        file.read_to_string(&mut value).unwrap();
        assert_eq!(value, "synthetic log");
        assert!(safe_open(&root.path().join("nginx/nested/access.log"), root.path()).is_err());
        assert!(safe_directory(root.path(), "../outside").is_err());
        assert!(safe_directory(root.path(), "nginx/nested").is_err());
        std::fs::write(outside.path().join("secret.log"), b"not allowed").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("linked")).unwrap();
        assert!(safe_directory(root.path(), "linked").is_err());
        assert!(safe_open(&root.path().join("linked/secret.log"), root.path()).is_err());
        let sidecar = log.with_extension("source.json");
        std::fs::write(&sidecar,serde_json::json!({"schema_version":1,"synthetic":true,"run_id":Uuid::new_v4(),"sha256":hash(b"synthetic log"),"year":2026,"timezone":"UTC"}).to_string()).unwrap();
        assert!(crate::log_formats::source_in_root(&log, root.path()).is_ok());
        std::fs::write(&sidecar, vec![b'x'; 16385]).unwrap();
        assert!(crate::log_formats::source_in_root(&log, root.path()).is_err());
        std::fs::remove_file(sidecar).unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret.log"),
            log.with_extension("source.json"),
        )
        .unwrap();
        assert!(crate::log_formats::source_in_root(&log, root.path()).is_err());
    }
    #[test]
    fn directory_swap_never_reads_an_external_file() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let directory = root.path().join("nginx");
        let parked = root.path().join("parked");
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("access.log"), b"allowed").unwrap();
        std::fs::write(outside.path().join("access.log"), b"outside canary").unwrap();
        let target = outside.path().to_path_buf();
        let changing = directory.clone();
        let writer = std::thread::spawn(move || {
            for _ in 0..200 {
                std::fs::rename(&changing, &parked).unwrap();
                std::os::unix::fs::symlink(&target, &changing).unwrap();
                std::fs::remove_file(&changing).unwrap();
                std::fs::rename(&parked, &changing).unwrap();
            }
        });
        for _ in 0..1000 {
            if let Ok(mut file) = safe_open(&directory.join("access.log"), root.path()) {
                let mut text = String::new();
                file.read_to_string(&mut text).unwrap();
                assert_eq!(text, "allowed");
            }
        }
        writer.join().unwrap();
    }
}
