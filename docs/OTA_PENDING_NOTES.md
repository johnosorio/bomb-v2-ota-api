# Checkpoint OTA — pendientes del backend

2026-09-23. Tag pareado `checkpoint/ota-03-pending-notes-2026-09-23`.
Base de implementación: `274fd91`, rama `feat/ota-phase1-foundation`;
repositorio firmware/documentación pareado: `dc003f0`, rama `master`.
Tag anterior: `checkpoint/ota-03-device-gateway-2026-09-22`.

Este cierre sólo añade notas; no modifica handlers, SQL, configuración ni firmware.
Evidencia previa: 59/59 tests Node y PostgreSQL 17.11 local, incluidos HTTP,
rol restringido, firma, concurrencia, revocación, rollback y reinicio.
No equivale a validación Supabase/TLS/Preview ni aceptación física.

## Continuación actualizada — 2026-09-30

El incremento [03.2c](OTA_CREDENTIAL_RECOVERY.md) añade recuperación/revocación/
reemplazo administrativo y sus pruebas. Su checkpoint original era local; la
validación remota posterior se recoge a continuación. Recuperación física CoreS3
sigue pendiente. El checkpoint/tag anterior se conserva como base.


1. API/DB de credenciales validadas en Development/Preview el 2026-09-30:
   [evidencia real](OTA_CREDENTIAL_PREVIEW_VALIDATION.md), código `1f12037`.
   Las migraciones `20260922000100`, `20260922000200` y `20260930000100` constan
   aplicadas junto a foundation. Rol dedicado LOGIN/TLS y firmante de prueba sólo
   en Previews protegidos. Inventario 24/24, credenciales 24/24, rutas 6/6 y
   persistencia entre dos despliegues comprobada; fixture sintético cerrado.
2. Falta administrador humano y vistas del portal, provisión/confirmación física
   de huella, almacenamiento durable y UI CoreS3. Las cuentas sintéticas quedaron
   baneadas y sin membresías; no son cuentas para operar el portal.
3. Cerrar límites perimetrales/IP, retención de retos/auditoría, rotación de claves
   de firma y recuperación operativa antes de exposición pública. La protección
   de Preview no es el acceso final para dispositivos físicos.
4. Integrar CoreS3: claves/verificador, SD cifrada/journal, reloj fiable,
   cliente no bloqueante, UI/guardas y aceptación física LIC-01…06.
5. Continuar artefactos/canales firmados, versionado, asignación/recibos, vistas
   administrativas y actualización/rollback. OTA completo sigue pendiente.

Checkpoint pareado: `checkpoint/ota-03-preview-2026-09-30`.
Flags apagadas por defecto en código; gateway sólo habilitado en el Preview
autorizado. No usar service-role, postgres o JWT humano como credencial del equipo.
CoreS3 0.2.36 y Bomb01 B01-GAME-13 conservan sus versiones estables verificadas.
Ante vencimiento/revocación conocida, conservar la ronda activa y bloquear nuevas
partidas/rondas, sin STOP a Bomb01. No hubo carga, promoción STABLE ni despliegue
de producción. Una carga posterior sigue requiriendo su autorización específica.

[Notas completas y decisiones del operador](../../firmware/OTA_PENDIENTES.md),
[contrato gateway](OTA_DEVICE_GATEWAY.md),
[administración](OTA_LICENSE_ADMINISTRATION.md).
