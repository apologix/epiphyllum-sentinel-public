use std::{fs, io::Write, path::Path};

pub fn initialize() -> anyhow::Result<()> {
    let root = Path::new("/secrets");
    for (name, env, generated) in [
        (
            "admin_secret",
            "ADMIN_SECRET",
            format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            ),
        ),
        (
            "master_key",
            "MASTER_KEY",
            format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            ),
        ),
    ] {
        let supplied = std::env::var(env).ok().filter(|s| !s.is_empty());
        let path = root.join(name);
        if path.exists() {
            let stored = fs::read_to_string(&path)?;
            anyhow::ensure!(
                supplied.as_ref().is_none_or(|v| *v == stored),
                "Conflicto de secreto persistido: {env}; conserve el maestro original"
            );
        } else {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(supplied.as_deref().unwrap_or(&generated).as_bytes())?;
            file.sync_all()?;
        }
    }
    Ok(())
}
pub fn read(env: &str, name: &str) -> anyhow::Result<String> {
    if let Ok(value) = std::env::var(env)
        && !value.is_empty()
    {
        return Ok(value);
    }
    Ok(fs::read_to_string(Path::new("/secrets").join(name))?)
}
