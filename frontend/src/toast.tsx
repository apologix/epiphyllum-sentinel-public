import { useEffect, useState } from "react";
import Toast from "@/components/arc/toast/toast";

// Sistema de notificaciones toast (UI-ARC-05, punto 17): usa el Toast de
// Arc ya instalado (components/arc/toast) para success/error/warning/info,
// nada de alert/confirm nativos para feedback. El Toast de Arc pinta su
// icono con la variable --success; cada variante la redefine en su
// contenedor (rojo/ámbar/azul) y antepone la etiqueta de la variante al
// título, para que el tipo no dependa solo del color.
export type ToastVariant = "success" | "error" | "warning" | "info";
export interface ToastItem {
  id: number;
  variant: ToastVariant;
  title: string;
  description?: string;
}

const VARIANT_LABEL: Record<ToastVariant, string> = {
  success: "Listo",
  error: "Error",
  warning: "Atención",
  info: "Aviso",
};
const VARIANT_COLOR: Record<ToastVariant, string> = {
  success: "#46a758",
  error: "#e5484d",
  warning: "#ffb224",
  info: "#6ea8fe",
};

let seq = 0;
let recent: { key: string; at: number }[] = [];
/** Muestra un toast Arc desde cualquier componente, sin prop drilling. */
export function notifyToast(variant: ToastVariant, title: string, description?: string) {
  // Deduplica el mismo aviso inmediato (por ejemplo, un refresco que falla en
  // varios componentes a la vez) sin ocultar avisos legítimamente repetidos.
  const key = `${variant}\u0000${title}\u0000${description ?? ""}`;
  const now = Date.now();
  recent = recent.filter((item) => now - item.at < 1500);
  if (recent.some((item) => item.key === key)) return;
  recent.push({ key, at: now });
  window.dispatchEvent(
    new CustomEvent("sentinel-toast", { detail: { variant, title, description } }),
  );
}

export function ToastHost() {
  const [items, setItems] = useState<ToastItem[]>([]);
  useEffect(() => {
    const handler = (event: Event) => {
      const detail = (event as CustomEvent).detail as Omit<ToastItem, "id">;
      const id = ++seq;
      setItems((current) => [...current.slice(-2), { ...detail, id }]);
    };
    window.addEventListener("sentinel-toast", handler);
    return () => window.removeEventListener("sentinel-toast", handler);
  }, []);
  if (!items.length) return null;
  return (
    <div className="toast-host" aria-label="Notificaciones del sistema" aria-live="polite" aria-relevant="additions text">
      {items.map((item) => (
        <div
          key={item.id}
          data-variant={item.variant}
          style={{ "--success": VARIANT_COLOR[item.variant] } as React.CSSProperties}
        >
          <Toast
            title={`${VARIANT_LABEL[item.variant]}: ${item.title}`}
            description={item.description}
            duration={item.variant === "error" ? 8000 : item.variant === "warning" ? 7000 : 5000}
            onOpenChange={(open) => {
              if (!open) setItems((current) => current.filter((i) => i.id !== item.id));
            }}
          />
        </div>
      ))}
    </div>
  );
}
