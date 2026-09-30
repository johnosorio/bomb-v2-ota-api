# OTA-03.2c — recuperación de credencial de dispositivo

Incremento local desde `e276937`, 2026-09-30. Migración forward
`20260930000100_ota_credential_recovery.sql`, posterior a foundation, administración
y gateway. No aprovisiona LOGIN, secretos ni habilita flags. Validación local
completada; Supabase/Preview y CoreS3 siguen pendientes.

## Problema y decisión

Revocar una concesión no retira una clave comprometida. Se amplía el RPC y
endpoint administrativo existentes, con su Auth/JWT humano, ámbito, lock de
membresía/dispositivo y recibos transaccionales. No se crea otro login ni endpoint
privilegiado. Actualizar sólo la huella perdería el historial, permitiría reutilizar
una clave retirada y no resolvería una baja sin sustitución inmediata.

El administrador autoriza la huella SHA-256 del SPKI P-256 canónico tras contrastarla
por un canal confiable con el equipo. La API de administración acepta la huella,
no una clave privada ni prueba de posesión: el gateway existente comprueba la
clave pública P-256 y firma fresca antes de entregar documentos. La clave perdida
no es requisito para recuperarse. No hay autoalta, cambio de MAC/ámbito, borrado
de identidad, reset de revisión ni modificación de LIMPIAR/reset de fábrica.

## Contrato administrativo

`POST /api/ota/licenses`, mismas flags `OTA_ADMIN_ENABLED` y
`OTA_LICENSE_ADMIN_ENABLED`; actor Auth no anónimo, admin actual del ámbito.
Campos comunes: `device_id`, `request_id`, `action`, `expected_revision`,
`expected_credential_id`, `reason`. Reason es exactamente `lost`, `compromised`
o `maintenance`: no texto libre donde puedan introducirse secretos.

| Acción | Campo adicional | Efecto |
| --- | --- | --- |
| `revoke_credential` | Ninguno | Sólo clave activa: la retira y bloquea challenge/exchange |
| `replace_credential` | `device_key_sha256` | Desde activa o retirada: retira la anterior y aprueba un UUID/huella nuevos |

Las acciones comprueban revisión **y** UUID actuales, incrementan la misma revisión
de concesión sin wrap uint32 y conservan `device_id`, MAC, ámbito, `license_id`,
estado de concesión y todas sus fechas. Reemplazar no renueva ni reactiva una
concesión vencida/revocada. `grant` con credencial retirada falla 409; `revoke`
de concesión sigue permitido. La nueva clave debe pasar challenge/exchange.

`credential_status: active|revoked` aparece en GET y nuevos recibos. `status`
sigue describiendo la concesión. Una clave activa no significa licencia vigente.
Antes de la primera concesión, `unlicensed` puede tener revisión mayor que cero
por recuperación; sus fechas siguen siendo null. Verificador/emisor Node admite
esa revisión sin alterar el formato firmado v1. CoreS3 0.2.36 aún no lo consume.

Cada huella/UUID queda en `ota_private.device_credentials`, incluida fecha/actor
de aprobación y de retiro, motivo y revisión de retiro. RLS activada, sin grants
de datos para anon/authenticated/service_role/gateway. Las huellas son únicas
globalmente para siempre: no reutilizar una clave retirada, tampoco en otro equipo.
La migración importa identidades existentes, recuperando autor/fecha de aprobación
del recibo original cuando existe. No altera recibos históricos previos.
La licencia actual referencia obligatoriamente ese historial por UUID/dispositivo/
huella; el gateway comprueba además que la entrada histórica no esté retirada.
La auditoría pública de ámbito mantiene su contrato previo: admin y viewer del
mismo ámbito pueden leer comandos, motivos y snapshots, todos sin secretos.
Privado describe el acceso directo al ledger, no oculta esos datos de auditoría
a miembros ya autorizados del ámbito.

## Atomicidad, reintento y concurrencia

Retiro/alta en historial, estado actual, revisión, eliminación de retos y auditoría
se confirman en una transacción. Fallar auditoría, unicidad o CAS revierte todo.
Los retos pendientes y consumidos de esa identidad se eliminan; las entregas
auditadas se conservan. El helper gateway exige credencial activa antes y después
del lock. Una revocación/reemplazo que gana el lock impide emitir con la clave vieja.
Si el exchange confirma primero, la respuesta ya emitida puede llegar después:
el punto de garantía es COMMIT, no el orden de llegada de paquetes.

Mismo dispositivo/request/actor/cuerpo devuelve recibo histórico idéntico, sin
mutar de nuevo. Autorización vigente se verifica antes incluso en replay. Colisión
de cuerpo/actor, revisión/UUID obsoletos, estado incompatible, huella ya usada o
revisión agotada: 409 `LICENSE_CONFLICT`. Validación: 400; sin Auth: 401; sin ámbito/
admin: 403; configuración/proveedor: 503. Ningún error expone SQL o ámbito ajeno.

Tras respuesta perdida, reintentar con mismo request/cuerpo; después GET. Un
recibo antiguo no autoriza al gateway ni debe usarse como estado actual. El handler
admite snapshots históricos anteriores sin `credential_status`, pero GET exige
la columna nueva. El RPC adjunta `receipt_version` de una columna persistida:
1 para operaciones previas, 2 para las nuevas; el adaptador HTTP retira ese
metadato y sólo tolera ausencia de estado de credencial en versión 1. El recibo
HTTP previo queda idéntico, también al reintentarlo después de una recuperación.
Un 409 requiere releer y confirmar una nueva decisión; no
reintentar automáticamente contra la última revisión. UI administrativa pendiente.

## Límites de recuperación

La revocación de clave cierra nuevas entregas online. No invalida instantáneamente
un documento offline ya emitido ni comunica revocación mediante un HTTP sin firma.
El dispositivo deberá persistir identidad/revisión y reloj fuera de una SD
transferible; esa integración sigue pendiente. La ronda activa termina y Bomb01
mantiene su contador/validación local. No se le envía STOP por licencia.

Aplicar las tres migraciones posteriores a foundation en orden requiere una
autorización remota específica. Desplegar este backend antes del esquema falla
cerrado; coordinar DB, verificador y backend con el gateway deshabilitado. No usar
un rollback que elimine historial: conservar los datos y corregir hacia delante.
Deshabilitar flags es un cierre HTTP, no revoca permisos RPC directos; el runbook
operativo debe considerar ambos. Preview con Auth/PostgREST/TLS reales, controles
de exposición, UI, provisión física y aceptación LIC-01…06 siguen abiertos.

## Evidencia local — 2026-09-30

- `npm test`: **63/63** pruebas Node, validación HTTP, metadato de recibos,
  firma/verificación y estado unlicensed con revisión posterior a recuperación.
- `OTA_TEST_PG_BIN=/opt/homebrew/opt/postgresql@17/bin npm run test:db`:
  **PostgreSQL 17.11 aislado**, socket privado sin TCP, detenido al terminar.
  Upgrade desde filas/recibos 03.2b, backfill del autor original y retry histórico;
  roles/RLS, credencial retirada rechazada, nueva clave y vigencia conservada,
  concesión revocada conservada, revocación/reemplazo mientras exchange espera
  el lock, dos reemplazos concurrentes (uno gana), huella histórica rechazada
  entre dispositivos, rollback íntegro de estado/historial/retos y reinicio.
- `git diff --check` y revisión independiente sin bloqueos al cierre.

Coordinador: contrato, SQL, Node, integración y ejecución de pruebas. `bomb_explorer`
(Luna low) inventarió el arnés; `bomb_backend` (Terra medium) preparó pruebas;
`bomb_reviewer` (Terra high) revisó seguridad. El coordinador corrigió y contrastó
el fixture de concurrencia (conexiones independientes), tipos bigint y la separación
entre retirada de clave y revocación de concesión antes de integrarlo. La revisión
motivó explicitar el metadato de recibos legacy y el vínculo obligatorio al historial.
Estas pruebas no acreditan Auth/PostgREST/TLS remotos ni recuperación en hardware.

Fuentes: [gateway](OTA_DEVICE_GATEWAY.md), [administración](OTA_LICENSE_ADMINISTRATION.md)
y [pendientes](OTA_PENDING_NOTES.md).
