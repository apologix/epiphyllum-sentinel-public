-- Ejecutar como root de MySQL en la VM. Cambiar las contraseñas por las
-- del archivo privado /etc/canario/canario.env (nunca en Git).
CREATE DATABASE IF NOT EXISTS canario CHARACTER SET utf8mb4;
CREATE USER IF NOT EXISTS 'canario_app'@'127.0.0.1' IDENTIFIED BY 'CAMBIAR_APP';
GRANT SELECT, INSERT, UPDATE, DELETE ON canario.* TO 'canario_app'@'127.0.0.1';
-- Usuario del Escenario B: SOLO lectura y SOLO sobre la vista pública.
-- OJO: el GRANT sobre talent_public solo funciona DESPUÉS de correr las
-- migraciones (la vista la crea 001_init.sql); si falla por eso, repetirlo al final.
CREATE USER IF NOT EXISTS 'canario_lab_ro'@'127.0.0.1' IDENTIFIED BY 'CAMBIAR_LAB';
GRANT SELECT ON canario.talent_public TO 'canario_lab_ro'@'127.0.0.1';
FLUSH PRIVILEGES;
