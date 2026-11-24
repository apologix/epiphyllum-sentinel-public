/** Configuración por entorno. Sin secretos en el repo: todo sale de env. */
export function loadConfig(env = process.env) {
  const labMode = (env.CANARIA_LAB_MODE || 'safe').toLowerCase();
  if (labMode !== 'safe' && labMode !== 'vulnerable') {
    throw new Error(`CANARIA_LAB_MODE inválido: ${env.CANARIA_LAB_MODE} (safe|vulnerable)`);
  }
  if (labMode === 'vulnerable') {
    // El modo vulnerable SOLO puede arrancar con la marca explícita de
    // aislamiento del laboratorio. Sin ella, el backend se niega a iniciar.
    if (env.CANARIA_LAB_ISOLATED !== '1') {
      throw new Error('CANARIA_LAB_MODE=vulnerable requiere CANARIA_LAB_ISOLATED=1 (VM aislada verificada). Arranque denegado.');
    }
    if (!env.CANARIA_LAB_ALLOWED_CIDR) {
      throw new Error('CANARIA_LAB_MODE=vulnerable requiere CANARIA_LAB_ALLOWED_CIDR (red autorizada del laboratorio).');
    }
  }
  return {
    port: Number(env.CANARIA_PORT || 3001),
    host: env.CANARIA_HOST || '127.0.0.1',
    labMode,
    labIsolated: env.CANARIA_LAB_ISOLATED === '1',
    labAllowedCidr: env.CANARIA_LAB_ALLOWED_CIDR || null,
    logDir: env.CANARIA_LOG_DIR || '/var/lib/epiphyllum-lab/logs/node',
    sessionSecret: process.env.CANARIA_SESSION_SECRET || 'dev-only-change-me',
    sessionTtlHours: Number(env.CANARIA_SESSION_TTL_HOURS || 12),
    loginMaxFailures: Number(env.CANARIA_LOGIN_MAX_FAILURES || 5),
    loginLockMinutes: Number(env.CANARIA_LOGIN_LOCK_MINUTES || 10),
    db: {
      host: env.CANARIA_DB_HOST || '127.0.0.1',
      port: Number(env.CANARIA_DB_PORT || 3306),
      database: env.CANARIA_DB_NAME || 'canario',
      user: env.CANARIA_DB_USER || 'canario_app',
      password: process.env.CANARIA_DB_PASSWORD || '',
      labUser: env.CANARIA_DB_LAB_USER || 'canario_lab_ro',
      labPassword: process.env.CANARIA_DB_LAB_PASSWORD || '',
    },
    labFilesDir: env.CANARIA_LAB_FILES_DIR || new URL('../../../lab-files', import.meta.url).pathname,
    outboxDir: env.CANARIA_OUTBOX_DIR || '/var/lib/canario/outbox',
    appVersion: env.CANARIA_APP_VERSION || '1.0.0',
  };
}
