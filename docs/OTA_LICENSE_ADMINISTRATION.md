# OTA-03.2a — administración persistente de licencias

Nota posterior: el [gateway 03.2b](OTA_DEVICE_GATEWAY.md) ya está implementado
y validado localmente. Este documento conserva el alcance administrativo;
ninguna de las dos migraciones nuevas se ha aplicado remotamente.

2026-09-22. Implementación **local**, posterior al checkpoint `68c621a`.
Migración forward `20260922000100_ota_license_administration.sql`, no aplicada
a Supabase. No despliegue Vercel, firma/emisión de documentos, activación real,
UI administrativa ni cambio de firmware en esta entrega.

## Frontera y decisión

Separar autorización administrativa de posesión física. El administrador del
ámbito fija el destino autorizado (MAC canónica y SHA-256 de SPKI DER P-256),
y concede/renueva/revoca su vigencia. **Eso no acredita posesión de la clave ni
autoriza a entregar un documento a quien declare esa MAC.** Un futuro gateway
debe exigir prueba firmada fresca, validar P-256/SPKI/huella y consultar estado
actual. Ningún handler de esta entrega importa `license-document.js`.

La huella debe contrastarse con la mostrada por el equipo, no con un heartbeat.
Ese recorrido de UI/clave aún no existe: no usar esta API como alta física real.
No hay reemplazo de identidad, traslado de ámbito, borrado ni autoalta. Un error
de vinculación requiere el futuro flujo de recuperación autorizado; no se
resuelve cambiando MAC o reutilizando una concesión de otro equipo.

Patrones acotados: reutilizar Auth/fetch bajo JWT humano y RLS del inventario;
RPC transaccional para estado + recibo/auditoría; revisión esperada para evitar
pisar una decisión administrativa posterior. Un Map no sobrevive a instancias;
dos escrituras HTTP independientes no garantizan atomicidad. No se incorpora
SDK, driver, CRM, colas, ni estado de partidas.

Decisión para **03.2b, aún no implementada**: gateway de equipo con rol PostgreSQL
dedicado, sin bypass RLS, acceso a tablas ni membresía de roles privilegiados,
EXECUTE sólo sobre RPC explícitas de challenge/consumo/consulta autorizada,
conexión server-side con TLS verificado. No JWT humano almacenado en CoreS3,
auto-registro de usuarios Supabase, service-role en handlers ni contraseña DB
en firmware. Antes de habilitarlo: validar grants/herencia, pool y aislamiento
en Preview; aprovisionamiento de credenciales requiere autorización aparte.
Este incremento administrativo no crea ese rol ni conexiones privilegiadas.

## API administrativa

`GET/POST /api/ota/licenses`, ambas flags exactamente `true`:
`OTA_ADMIN_ENABLED` y `OTA_LICENSE_ADMIN_ENABLED`. Nueva flag apagada por defecto.
Supabase URL HTTPS/publishable key y Bearer del usuario verificado por Auth.
Sin cookies, CORS abierto, service-role, fallback en memoria ni claves privadas.

- GET `?device_id=<UUID ota_devices.id>`: miembro admin o viewer del ámbito.
  Responde `{schema_version:1,license:<estado actual o null>}`. `null` significa
  dispositivo accesible aún sin identidad aprobada. Ajeno/inexistente: 403.
- POST JSON: campos comunes `device_id`, `request_id` (UUID, ámbito de
  idempotencia **por dispositivo**), más una de estas operaciones exactas:

| action | Campos adicionales | Precondición y efecto |
| --- | --- | --- |
| approve_identity | mac, device_key_sha256 | Sin fila previa; crea destino administrativo `unlicensed`, revisión 0 |
| grant | expected_revision, not_before, expires_at | Desde unlicensed/granted/revoked; CAS correcto, revisión +1 y estado granted |
| revoke | expected_revision | Sólo desde granted; CAS correcto, revisión +1 y estado revoked; conserva fechas |

POST requiere admin vigente. UUID normalizados a minúsculas en HTTP. MAC seis
octetos mayúsculos separados por `:`; huella 64 hex minúsculos. No otros campos:
el cliente no elige actor, licencia/credencial, estado, modelo ni fecha de emisión.
Revisión esperada 0…4294967295; fechas UTC enteras 1…4294967295, not_before <
expires_at. Para grant, expires_at debe superar el reloj DB al aplicar. Se
admite concesión futura, pero no habilita acceso antes de not_before. El DB
asigna issued_at; expiración no muta automáticamente status: `granted` significa
concesión administrativa, **no** licencia actualmente vigente ni equipo activado.
Tras agotar revisión, falla sin wrap; no hay reset de ese contador.

200 POST: `{schema_version:1,receipt:{device_id,request_id,action,snapshot}}`.
El snapshot es un acuse **histórico**, nunca permiso vigente ni entrada para
el firmante. Después de actuar o reintentar, volver a consultar GET para pintar
el estado actual. Dos admins compitiendo: uno gana CAS y el otro recibe 409;
releer y pedir nueva confirmación, no renovar automáticamente contra la nueva
revisión. Renovar después de revocación exige expected_revision de esa revocación.

## Reintentos, errores y regreso

- Timeout/respuesta perdida: mantener request_id y cuerpo exactos para reintentar.
  Mismo dispositivo/request/actor/comando devuelve recibo original aunque haya
  cambios posteriores; no vuelve a mutar ni duplicar auditoría. Mismo ID con
  otro actor/comando: 409 `LICENSE_CONFLICT`. Un ID nuevo es una operación nueva.
- La autorización actual se comprueba antes de recuperar el recibo: perder
  membresía impide recuperar/modificar datos antiguos por este endpoint.
- 400 entrada inválida; 401 JWT ausente/inválido; 403 sin ámbito/rol suficiente;
  409 identidad ya vinculada/reutilizada, CAS o transición incompatible;
  405 método; 413 tamaño; 415 JSON requerido; 503 flag apagada/configuración/
  proveedor/red. Detalles SQL/tokens no salen al cliente. Identidad global única
  puede revelar indisponibilidad genérica, nunca datos del ámbito contrario.
- Cada petición al proveedor vence a 5 s. Si una mutación pudo haber llegado a
  DB, un 503 no demuestra rollback; resolver mediante reintento exacto y GET.
- Pantalla futura: conservar origen/entrada en carga/error, mostrar acuse sin
  confundirlo con activación, reconsultar al volver. Cancelar visualmente no
  deshace una transacción enviada. **Es comportamiento exigido, no UI creada.**
- JSON normalizado y Content-Length limitados a 4096 bytes. Sin longitud y con
  body preparseado, el límite de bytes originales corresponde a la plataforma;
  Preview sigue pendiente, igual que inventario.
  El RPC directo limita además el comando a 4096 bytes de representación JSONB
  antes de bloquear filas/recorrer campos; no mide los bytes originales HTTP.

## DB, permisos y atomicidad

`ota_device_licenses`: una fila por dispositivo **aprobado**, FK al inventario,
credential_id/license_id estables generados por DB; MAC/huella globalmente únicas;
estado, revisión, fechas y último actor. No claves privadas ni códigos de juego.
`ota_license_operations`: PK (device_id,request_id), actor derivado de auth.uid,
comando, snapshot y hora; es la auditoría de operaciones administrativas exitosas.
No purgar recibos mientras puedan llegar reintentos: retención automatizada no
implementada. Errores rechazados no generan auditoría de éxito ni se registran
copiando cuerpos/tokens en logs.

SELECT con RLS para miembros no anónimos; sin DML directo ni EXECUTE para
PUBLIC/anon/service_role. RPCs `ota_get_device_license` y `ota_admin_license`
SECURITY DEFINER con search_path vacío, nombres cualificados, control de actor
y ámbito. Mutación bloquea membresía admin y fila de inventario (FOR SHARE / FOR
UPDATE); serializa primera aprobación, CAS y recibos. Si falla auditoría,
rollback del estado y revisión. La revocación de membresía espera una operación
ya autorizada; no invalida retrospectivamente su commit.

Grants/RLS se prueban también entrando directamente al RPC: el handler no es
la única barrera. Las flags sólo bloquean Vercel, **no** RPC directo Supabase
tras aplicar migración. Apagado completo requiere retirar grants/membresías.

## Comprobación y puesta en servicio pendiente

`npm test`: HTTP/proveedor simulado, firma aislada y compatibilidad demo/inventario.
Resultado local final: **44/44** (10 tests nuevos de administración HTTP).
`OTA_TEST_PG_BIN=/opt/homebrew/opt/postgresql@17/bin npm run test:db`: PostgreSQL
17.11 real y desechable, socket privado sin TCP ni credenciales externas. Incluye
RLS/grants, campos inválidos/direct RPC, transiciones, colisiones, recibo histórico,
revocación, rollback por fallo de auditoría, límite de revisión, 8 aprobaciones
concurrentes idénticas, concesiones concurrentes y carrera renovar/revocar, más
reinicio y repetición conservando estado/recibos. No prueba Auth/JWT/PostgREST
reales para estas nuevas rutas; exige Preview antes de habilitación.

Trabajo: coordinador para contrato/SQL/HTTP/integración; Terra medium para ocho
tests HTTP iniciales, Terra high para revisión independiente. El coordinador
añadió dos tests de identidad/respuesta. Revisión detectó límite ausente en RPC
directo; corregido antes de los locks y cubierto por SQL sobredimensionado.
No se ejecutó PlatformIO ni se accedió al hardware en este incremento.

Orden futuro: revisión/permiso para migración development → aplicar forward →
provisionar admin humano fuera de chat → configurar flag sólo en Preview →
probar Auth y forma JSON real de los RPC, ámbitos, CAS y reintentos → gateway y
CoreS3. Sin emisión segura, no permitir que estos datos activen el modo juego.
Rollback operativo: deshabilitar flag/volver API anterior; conservar tablas y
auditoría, no DROP ni down destructivo. Firmware 0.2.36/B01-GAME-13 y rutas demo
no cambian. LIC-01…06 y validación física siguen pendientes.

Referencias primarias: [funciones Supabase](https://supabase.com/docs/guides/database/functions),
[RLS Supabase](https://supabase.com/docs/guides/database/postgres/row-level-security),
[bloqueos PostgreSQL 17](https://www.postgresql.org/docs/17/explicit-locking.html).
