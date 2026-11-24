// Logo propio de Epiphyllum Sentinel (UI-ARC-05, punto 6): una hoja de
// epiphyllum (la flor nocturna que se abre de noche, como un centinela)
// cuyo centro es un ojo/pupila en el azul de acento de Arc. SVG inline,
// sin assets externos: se usa en la barra lateral, el login y el favicon
// (data URI en index.html con la misma geometría).
export function SentinelLogo({ size = 34 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      role="img"
      aria-label="Epiphyllum Sentinel"
      className="sentinel-logo"
    >
      {[0, 45, 90, 135, 180, 225, 270, 315].map((a) => (
        <ellipse
          key={a}
          cx="24"
          cy="14.5"
          rx="4.6"
          ry="11"
          stroke="#8b9bab"
          strokeWidth="1.5"
          transform={`rotate(${a} 24 24)`}
        />
      ))}
      <circle cx="24" cy="24" r="7.2" fill="#0b1e3a" stroke="#6ea8fe" strokeWidth="1.8" />
      <circle cx="24" cy="24" r="3.1" fill="#6ea8fe" />
      <circle cx="25.4" cy="22.6" r="1" fill="#dbeafe" />
    </svg>
  );
}
