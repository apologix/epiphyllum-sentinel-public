/** Datos ficticios coherentes y deterministas (sin RNG en runtime).
 * Correos en dominios reservados (.example / ficticios .cr de la empresa).
 * Las contraseñas demo NO viven aquí: se crean desde env en seed.js. */
export const SERVICES = [
  { slug: 'desarrollo-de-software', name: 'Desarrollo de software', summary: 'Equipos dedicados que diseñan, construyen y mantienen productos digitales a la medida.', benefits: ['Arquitectura escalable', 'Entregas por iteraciones', 'Calidad verificable'], capabilities: ['Aplicaciones web', 'APIs e integraciones', 'Modernización de sistemas'], modalities: ['Equipo dedicado', 'Proyecto cerrado', 'Staff augmentation'], stack: ['Node.js', 'React', 'PostgreSQL', 'MySQL'] },
  { slug: 'staff-augmentation', name: 'Staff augmentation', summary: 'Especialistas senior que se integran a tu equipo en días, no meses.', benefits: ['Incorporación en 5-10 días', 'Perfiles verificados', 'Escala flexible'], capabilities: ['Frontend', 'Backend', 'QA', 'DevOps'], modalities: ['Por perfil', 'Por célula'], stack: ['React', 'TypeScript', 'Go', 'Python'] },
  { slug: 'soporte-y-operaciones-it', name: 'Soporte y operaciones IT', summary: 'Mesa de ayuda y operación continua con acuerdos de nivel de servicio medibles.', benefits: ['Cobertura extendida', 'SLA transparentes', 'Reportes mensuales'], capabilities: ['Mesa de ayuda N1/N2', 'Monitoreo', 'Administración de plataformas'], modalities: ['Remoto', 'Híbrido'], stack: ['Linux', 'Windows Server', 'Redes'] },
  { slug: 'ciberseguridad', name: 'Ciberseguridad', summary: 'Operación defensiva, monitoreo y respuesta con criterio humano y evidencia.', benefits: ['Monitoreo de eventos', 'Revisiones periódicas', 'Concientización'], capabilities: ['SOC', 'Gestión de vulnerabilidades', 'Respuesta a incidentes'], modalities: ['Servicio gestionado', 'Consultoría'], stack: ['SIEM', 'EDR', 'Hardening'] },
  { slug: 'data-y-analytics', name: 'Data & Analytics', summary: 'Datos ordenados y tableros que la dirección sí entiende.', benefits: ['Fuentes unificadas', 'Indicadores confiables', 'Automatización de reportes'], capabilities: ['Ingeniería de datos', 'BI', 'Calidad de datos'], modalities: ['Proyecto', 'Equipo dedicado'], stack: ['Python', 'SQL', 'Power BI'] },
  { slug: 'business-process-outsourcing', name: 'Business Process Outsourcing', summary: 'Procesos administrativos y de atención operados con disciplina y trazabilidad.', benefits: ['Costos predecibles', 'Procesos documentados', 'Mejora continua'], capabilities: ['Back office', 'Atención al cliente', 'Procesamiento documental'], modalities: ['Remoto', 'En sitio'], stack: ['CRM', 'Automatización RPA'] },
];
export const INDUSTRIES = [
  { slug: 'finanzas', name: 'Finanzas', description: 'Operación y tecnología para entidades financieras reguladas.' },
  { slug: 'salud', name: 'Salud', description: 'Sistemas y soporte para clínicas, laboratorios y aseguradoras de salud.' },
  { slug: 'comercio', name: 'Comercio', description: 'Plataformas de venta, logística e inventario para retail y distribución.' },
  { slug: 'educacion', name: 'Educación', description: 'Plataformas de aprendizaje y gestión académica.' },
  { slug: 'tecnologia', name: 'Tecnología', description: 'Equipos extendidos para empresas de software y SaaS.' },
  { slug: 'logistica', name: 'Logística', description: 'Trazabilidad, rutas y operación para transporte y bodegas.' },
];
export const CASE_STUDIES = [
  { slug: 'banca-digital-nova', company: 'Nova Pagos (ficticia)', industry: 'finanzas', service: 'desarrollo-de-software', problem: 'La pasarela heredada fallaba en picos de demanda y cada despliegue tomaba un fin de semana.', solution: 'Replataforma por etapas con equipo dedicado de 6 personas y observabilidad desde el día uno.', result: 'Datos de demostración: despliegues semanales y caída sostenida de incidentes en producción.' },
  { slug: 'clinica-portal-pacientes', company: 'Clínica Alba (ficticia)', industry: 'salud', service: 'staff-augmentation', problem: 'El portal de pacientes llevaba 14 meses detenido por falta de perfiles frontend.', solution: 'Célula de 3 especialistas integrada al equipo interno con tablero compartido.', result: 'Datos de demostración: portal publicado en dos trimestres y agenda digital adoptada por recepción.' },
  { slug: 'retail-inventario-tiempo-real', company: 'Distribuidora Bruma (ficticia)', industry: 'comercio', service: 'data-y-analytics', problem: 'El inventario se consolidaba a mano y las diferencias se descubrían al cierre del mes.', solution: 'Pipeline de datos diario con alertas de diferencia y tablero por bodega.', result: 'Datos de demostración: diferencias detectadas el mismo día y cierre mensual más corto.' },
];
const FIRST = ['María', 'José', 'Ana', 'Carlos', 'Lucía', 'Diego', 'Fernanda', 'Andrés', 'Valeria', 'Marco', 'Sofía', 'Ricardo', 'Elena', 'Tomás', 'Paula'];
const LAST = ['Solano', 'Quesada', 'Mora', 'Vargas', 'Rojas', 'Camacho', 'Araya', 'Cordero', 'Salas', 'Ureña', 'Pacheco', 'Loría', 'Brenes', 'Castro', 'Herrera'];
const ROLES_T = ['Desarrolladora backend', 'Desarrollador frontend', 'Ingeniera de datos', 'Especialista QA', 'DevOps', 'Analista de soporte N2', 'Consultora de ciberseguridad', 'Gestor de proyectos', 'Diseñadora UX', 'Analista BPO'];
export function buildConsultants() {
  const out = [];
  for (let i = 0; i < 54; i++) {
    const name = `${FIRST[i % 15]} ${LAST[(i * 7) % 15]} ${LAST[(i * 3 + 5) % 15]}`;
    out.push({ id: i + 1, name, specialty: ROLES_T[i % ROLES_T.length], years: 2 + (i % 11), availability: i % 5 === 0 ? 'En proyecto' : 'Disponible', status: 'activo', skills: ['Node.js', 'React', 'MySQL', 'Linux', 'Python', 'SQL'][i % 6] });
  }
  return out;
}
export const ORGANIZATIONS = [
  { id: 1, name: 'Nova Pagos S.A. (ficticia)', industry: 'finanzas', country: 'Costa Rica', size: '201-500' },
  { id: 2, name: 'Clínica Alba (ficticia)', industry: 'salud', country: 'Costa Rica', size: '51-200' },
  { id: 3, name: 'Distribuidora Bruma (ficticia)', industry: 'comercio', country: 'Costa Rica', size: '51-200' },
  { id: 4, name: 'EducaAndes (ficticia)', industry: 'educacion', country: 'Colombia', size: '11-50' },
  { id: 5, name: 'SaaS Andina (ficticia)', industry: 'tecnologia', country: 'México', size: '11-50' },
  { id: 6, name: 'TransRuta (ficticia)', industry: 'logistica', country: 'Panamá', size: '201-500' },
];
const PROJ = ['Plataforma de pagos v2', 'Portal de pacientes', 'Inventario en tiempo real', 'LMS corporativo', 'Migración SaaS multi-región', 'Trazabilidad de rutas', 'Mesa de ayuda unificada', 'SOC gestionado', 'Tablero ejecutivo BI', 'Automatización back office', 'App móvil de campo', 'Modernización core', 'Integración CRM', 'Pipeline de datos clínicos', 'Renovación e-commerce'];
export function buildProjects(consultants) {
  return PROJ.map((name, i) => ({
    id: i + 1, organization_id: (i % 6) + 1, name,
    status: ['activo', 'activo', 'en riesgo', 'activo', 'completado'][i % 5],
    priority: ['alta', 'media', 'baja'][i % 3],
    manager: consultants[(i * 4) % consultants.length].name,
    start_date: `2026-0${1 + (i % 6)}-15`, target_date: `2026-${String(7 + (i % 6)).padStart(2, '0')}-30`,
    progress: [15, 30, 45, 60, 75, 90, 100][i % 7],
    description: `Proyecto ficticio de demostración: ${name.toLowerCase()} para cliente ficticio, con hitos y equipo asignado.`,
  }));
}
export const JOBS = [
  ['desarrollador-backend-node', 'Desarrollador backend Node.js', 'Tecnología', 'Remoto', 'Senior', 'San José, CR', 'Node.js, MySQL, APIs REST'],
  ['desarrolladora-frontend-react', 'Desarrolladora frontend React', 'Tecnología', 'Híbrido', 'Semi-senior', 'San José, CR', 'React, TypeScript, accesibilidad'],
  ['ingeniero-de-datos', 'Ingeniero de datos', 'Datos', 'Remoto', 'Senior', 'Regional', 'Python, SQL, pipelines'],
  ['analista-soc-n1', 'Analista SOC N1', 'Ciberseguridad', 'Remoto', 'Junior', 'Regional', 'Monitoreo, triage, documentación'],
  ['especialista-qa', 'Especialista QA automatización', 'Tecnología', 'Remoto', 'Semi-senior', 'Regional', 'Playwright, pruebas API'],
  ['devops-junior', 'DevOps junior', 'Operaciones', 'Híbrido', 'Junior', 'San José, CR', 'Linux, CI/CD, Nginx'],
  ['gestor-de-proyectos', 'Gestor de proyectos tecnológicos', 'Operaciones', 'Híbrido', 'Senior', 'San José, CR', 'Scrum, clientes, riesgos'],
  ['disenadora-ux', 'Diseñadora UX/UI', 'Diseño', 'Remoto', 'Semi-senior', 'Regional', 'Figma, sistemas de diseño'],
  ['analista-soporte-n2', 'Analista de soporte N2', 'Operaciones', 'Remoto', 'Junior', 'Regional', 'Mesa de ayuda, SLA'],
  ['consultor-bpo', 'Consultor de procesos BPO', 'BPO', 'En sitio', 'Semi-senior', 'San José, CR', 'Procesos, RPA, documentación'],
  ['arquitecto-de-soluciones', 'Arquitecto de soluciones', 'Tecnología', 'Remoto', 'Senior', 'Regional', 'Arquitectura cloud, integraciones'],
  ['administrador-mysql', 'Administrador MySQL', 'Datos', 'Remoto', 'Senior', 'Regional', 'MySQL 8, respaldo, rendimiento'],
].map(([slug, title, area, modality, level, location, tech], i) => ({ id: i + 1, slug, title, area, modality, level, location, tech, status: 'abierta', description: `Vacante ficticia de demostración para ${title}. Responsabilidades: ejecutar el trabajo del área con estándares de Canario, documentar y colaborar con el equipo asignado. Requisitos: experiencia comprobable en ${tech}.` }));
