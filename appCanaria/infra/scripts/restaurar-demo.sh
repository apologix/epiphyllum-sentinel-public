#!/bin/sh
# Restaura los datos de demostración: TRUNCATE de tablas de Canario y
# reseed. SOLO base canario; pide confirmación; jamás toca Sentinel.
set -eu
printf "Esto BORRA los datos de la base canario y vuelve a sembrar. Escribí RESTAURAR: "; read -r r; [ "$r" = "RESTAURAR" ] || { echo Cancelado; exit 1; }
mysql canario -e "SET FOREIGN_KEY_CHECKS=0; TRUNCATE users; TRUNCATE sessions; TRUNCATE password_resets; TRUNCATE organizations; TRUNCATE services; TRUNCATE industries; TRUNCATE case_studies; TRUNCATE jobs; TRUNCATE job_applications; TRUNCATE contact_leads; TRUNCATE quote_requests; TRUNCATE projects; TRUNCATE consultants; TRUNCATE talent_directory; TRUNCATE project_members; TRUNCATE project_milestones; TRUNCATE tickets; TRUNCATE ticket_comments; TRUNCATE documents; TRUNCATE invoices; TRUNCATE activities; SET FOREIGN_KEY_CHECKS=1;"
npm --prefix /srv/outsourcing-canario/backend run seed
echo "Datos de demostración restaurados."
