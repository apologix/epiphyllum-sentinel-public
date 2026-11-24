"""Adaptadores por servicio del servidor MCP del laboratorio.

Cada adaptador traduce una línea de log a cero o más eventos derivados
del contrato (planning/MCP-EVENT-CONTRACT.md). Un recurso sin adaptador
registrado sale exactamente como antes: el registro conserva su texto y
ningún derivado. Hay un único servidor MCP con adaptadores por servicio;
no existen servidores por servicio.

logs://mysql/audit NO tiene adaptador activo a propósito: el parser de
auditoría (mysql.audit_events) está implementado contra el formato
documentado del plugin, pero queda pendiente de validación contra la
instalación real de la VM antes de activarlo. No se simula que funciona.
"""
from . import mysql, nginx, nodejs, openssh

ADAPTERS = {
    'logs://nginx/access': nginx.adapt_access,
    'logs://nginx/error': nginx.adapt_error,
    'logs://mysql/error': mysql.adapt_error,
    'logs://node/app': nodejs.adapt,
    'logs://node/security': nodejs.adapt,
    'logs://ssh/auth': openssh.adapt,
}
