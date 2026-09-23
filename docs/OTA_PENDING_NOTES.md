# Checkpoint OTA — pendientes del backend

2026-09-23. Tag pareado `checkpoint/ota-03-pending-notes-2026-09-23`.
Base de implementación: `274fd91`, rama `feat/ota-phase1-foundation`;
repositorio firmware/documentación pareado: `dc003f0`, rama `master`.
Tag anterior: `checkpoint/ota-03-device-gateway-2026-09-22`.

Este cierre sólo añade notas; no modifica handlers, SQL, configuración ni firmware.
Evidencia previa: 59/59 tests Node y PostgreSQL 17.11 local, incluidos HTTP,
rol restringido, firma, concurrencia, revocación, rollback y reinicio.
No equivale a validación Supabase/TLS/Preview ni aceptación física.

## Continuación

1. Completar recuperación, revocación y reemplazo autorizado de credencial propia;
   la revocación de concesión ya implementada no sustituye revocar una clave.
2. Con autorización separada: revisar/aplicar las migraciones pendientes
   `20260922000100` y `20260922000200`; provisionar administrador humano y
   LOGIN/contraseña del rol gateway, firmante y configuración segura en development.
   Validar Auth/PostgREST, TLS/pooler, permisos efectivos y reintentos en Preview.
   Sólo consta aplicada remotamente `20260921000100`; no asumir DDL por un push.
3. Cerrar límites perimetrales/IP, retención de retos/auditoría, rotación de claves
   de firma y recuperación operativa antes de exposición pública.
4. Integrar después CoreS3: claves/verificador, SD cifrada/journal, reloj fiable,
   cliente no bloqueante, UI/guardas y aceptación física LIC-01…06.
5. Continuar artefactos/canales firmados, versionado, asignación/recibos, vistas
   administrativas y actualización/rollback. OTA completo sigue pendiente.

Gateway desactivado por defecto; rol NOLOGIN hasta aprovisionamiento autorizado.
No usar service-role, postgres o JWT humano como credencial del equipo.
No publicar secretos ni ejecutar migración/despliegue/flash como parte del cierre.
Un push puede generar Preview automático; no habilita flags ni prueba funcionalidad.
CoreS3 0.2.36 y Bomb01 B01-GAME-13 no cambian. Ante vencimiento/revocación conocida,
conservar la ronda activa y bloquear nuevas partidas/rondas, sin STOP a Bomb01.

[Notas completas y decisiones del operador](../../bomb-v2/OTA_PENDIENTES.md),
[contrato gateway](OTA_DEVICE_GATEWAY.md),
[administración](OTA_LICENSE_ADMINISTRATION.md).
