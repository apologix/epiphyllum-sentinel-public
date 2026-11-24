use crate::{
    contracts::{LogEvent, parse_line},
    hash,
};
use std::{collections::HashSet, io::Write, path::Path};
use uuid::Uuid;
const DATA: &[u8] = include_bytes!("../../datasets/conference-v1.ndjson");
const MANIFEST: &str = include_str!("../../datasets/conference-v1.manifest.json");
fn validate(bytes: &[u8], expected_hash: &str) -> anyhow::Result<Vec<LogEvent>> {
    anyhow::ensure!(
        bytes.len() <= 1048576 && bytes.ends_with(b"\n") && hash(bytes) == expected_hash,
        "dataset_integrity_invalid"
    );
    let mut events = Vec::new();
    let mut ids = HashSet::new();
    let mut run = None;
    for line in bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        let e = parse_line(line)?;
        anyhow::ensure!(
            e.seq == events.len() as u64 + 1 && ids.insert(e.event_id),
            "dataset_identity_invalid"
        );
        anyhow::ensure!(
            run.is_none_or(|r| r == e.scenario_run_id),
            "dataset_mixed_run"
        );
        run = Some(e.scenario_run_id);
        events.push(e);
    }
    anyhow::ensure!(events.len() == 48, "dataset_count_invalid");
    Ok(events)
}
pub fn load(root: &Path, run: Uuid) -> anyhow::Result<()> {
    anyhow::ensure!(
        root == Path::new("/data/logs")
            && !std::fs::symlink_metadata(root)?.file_type().is_symlink(),
        "dataset_output_denied"
    );
    let manifest: serde_json::Value = serde_json::from_str(MANIFEST)?;
    let mut events = validate(DATA, manifest["sha256"].as_str().unwrap())?;
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        anyhow::ensure!(
            !entry
                .file_name()
                .to_string_lossy()
                .starts_with(&run.to_string()),
            "El run ya existe; use otro UUID"
        );
    }
    let mut bytes = Vec::new();
    for e in &mut events {
        e.scenario_run_id = run;
        e.event_id = Uuid::new_v5(&run, format!("conference-v1:42:{}", e.seq - 1).as_bytes());
        serde_json::to_writer(&mut bytes, e)?;
        bytes.push(b'\n');
    }
    // Publish only a completely validated file. Collector ignores the staging extension.
    let staging = root.join(format!("{run}.staging"));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staging)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    let target = root.join(format!("{run}.ndjson"));
    std::fs::hard_link(&staging, &target)?;
    std::fs::remove_file(staging)?;
    let mut output = manifest;
    output["run_id"] = serde_json::json!(run);
    output["loaded_sha256"] = serde_json::json!(hash(&bytes));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join(format!("{run}.manifest.json")))?
        .write_all(&serde_json::to_vec_pretty(&output)?)?;
    println!(
        "{}",
        serde_json::json!({"run_id":run,"events":48,"scenario":"conference-v1","expected":{"incidents":4,"evidence":{"R1":12,"R2":7,"R3":12,"R4":1}}})
    );
    Ok(())
}
pub fn load_native(root: &Path, run: Uuid, extra: bool) -> anyhow::Result<()> {
    anyhow::ensure!(
        root == Path::new("/data/logs")
            && !std::fs::symlink_metadata(root)?.file_type().is_symlink(),
        "dataset_output_denied"
    );
    let files: &[(&str, &[u8])] = if extra {
        &[
            (
                "apache_error_normal",
                include_bytes!("../../datasets/native/apache_error_normal.log"),
            ),
            (
                "authlog_normal",
                include_bytes!("../../datasets/native/authlog_normal.log"),
            ),
            (
                "haproxy_normal",
                include_bytes!("../../datasets/native/haproxy_normal.log"),
            ),
            (
                "haproxy_attack",
                include_bytes!("../../datasets/native/haproxy_attack.log"),
            ),
            (
                "syslog_normal",
                include_bytes!("../../datasets/native/syslog_normal.log"),
            ),
            (
                "syslog_port_scan",
                include_bytes!("../../datasets/native/syslog_port_scan.log"),
            ),
        ]
    } else {
        &[
            (
                "authlog_brute_force",
                include_bytes!("../../datasets/native/authlog_brute_force.log"),
            ),
            (
                "nginx_error_attack",
                include_bytes!("../../datasets/native/nginx_error_attack.log"),
            ),
            (
                "apache_error_attack",
                include_bytes!("../../datasets/native/apache_error_attack.log"),
            ),
            (
                "nginx_error_normal",
                include_bytes!("../../datasets/native/nginx_error_normal.log"),
            ),
        ]
    };
    for entry in std::fs::read_dir(root)? {
        anyhow::ensure!(
            !entry?
                .file_name()
                .to_string_lossy()
                .starts_with(&run.to_string()),
            "El run ya existe; use otro UUID"
        );
    }
    for &(name, bytes) in files {
        let base = root.join(format!("{run}-{name}"));
        let meta = serde_json::json!({"schema_version":1,"synthetic":true,"run_id":run,"sha256":hash(bytes),"year":2026,"timezone":"UTC"});
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(base.with_extension("source.json"))?
            .write_all(&serde_json::to_vec_pretty(&meta)?)?;
        let staging = base.with_extension("staging");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::hard_link(&staging, base.with_extension("log"))?;
        std::fs::remove_file(staging)?;
    }
    println!(
        "{}",
        serde_json::json!({"run_id":run,"dataset":if extra {"native-logtriage-extra-v1"}else{"native-logtriage-v1"},"files":files.len(),"conversion":false})
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bundled_integrity_schema_and_identity() {
        let m: serde_json::Value = serde_json::from_str(MANIFEST).unwrap();
        assert_eq!(
            validate(DATA, m["sha256"].as_str().unwrap()).unwrap().len(),
            48
        );
        assert!(validate(DATA, "wrong").is_err());
        for bytes in [
            b"bad\n".to_vec(),
            DATA[..DATA.len() - 1].to_vec(),
            [DATA, DATA].concat(),
        ] {
            assert!(validate(&bytes, &hash(&bytes)).is_err());
        }
        let mut lines: Vec<serde_json::Value> = DATA
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_slice(l).unwrap())
            .collect();
        lines[1]["event_id"] = lines[0]["event_id"].clone();
        let bytes = lines
            .iter()
            .map(|v| format!("{v}\n"))
            .collect::<String>()
            .into_bytes();
        assert!(validate(&bytes, &hash(&bytes)).is_err());
    }
}
