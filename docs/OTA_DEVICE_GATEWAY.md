# OTA-03.2b — prueba de posesión y entrega de licencia

2026-09-22. Implementación de backend **probada localmente** sobre `edf0475`.
No migración remota, aprovisionamiento de secretos, promoción de producción ni
carga de firmware. El endpoint está apagado por defecto. CoreS3 0.2.36 y
Bomb01 B01-GAME-13 siguen instalados; aún no son clientes de este protocolo.

## Fronteras y decisiones

Reutiliza la [concesión administrativa](OTA_LICENSE_ADMINISTRATION.md), no sus
recibos históricos. Un admin autoriza MAC/huella y vigencia; el gateway acredita
posesión de P-256 y consume un reto fresco para consultar la concesión actual.
La MAC identifica, no autentica. No se auto-registra inventario, usuario Auth,
identidad o licencia. No se convierte la demo en autoridad.

Primera conexión: el CoreS3 no tiene todavía UUID de inventario/credencial.
Solicita reto con MAC, clave pública y prueba firmada. El servidor resuelve
el vínculo administrativo único por MAC + huella y devuelve esos UUID. Se
conservan como candidatos hasta verificar la respuesta firmada final; no deben
persistirse como identidad fiable sólo por recibir un challenge sin firma.

Se añade `pg` 8.23.0 fijado con lockfile porque el gateway necesita una
transacción SQL que abarque lectura bloqueada, consumo, auditoría y firma.
Una segunda llamada PostgREST independiente dejaría una ventana de revocación;
guardar JWT humano o usar service-role en esta ruta ampliaría autoridad.
Administración continúa con Auth/JWT/RLS; el gateway usa un rol SQL distinto.

## Protocolo v1

POST JSON `/api/ota/device-license`, sin JWT humano ni cookies. Payload
normalizado <=4096 bytes; Content-Length también comprobado. Body preparseado
sin longitud conserva la limitación de wire bytes pendiente de validar en Preview.
No query strings ni CORS abierto. Responses no-store; ningún token/cuerpo se loguea.

| action | Campos exactos adicionales | Resultado |
| --- | --- | --- |
| challenge | mac, public_key, client_nonce, signature | schema_version:1, challenge |
| exchange | device_id, credential_id, mac, public_key, client_nonce, challenge_id, nonce, signature | schema_version:1, status_document, license_document |

UUID minúsculos; MAC seis octetos hex mayúsculos con `:`. `public_key`: SPKI DER
P-256 sin compresión, 91 bytes, base64url canónico sin padding; importar y
reexportar debe conservar los bytes. SHA-256 de esos bytes debe coincidir con
el destino aprobado. `client_nonce` y nonce del servidor: 32 bytes aleatorios
representados por 64 hex minúsculos. `signature`: ECDSA SHA-256, IEEE-P1363 R||S
64 bytes, base64url canónico. No DER, claves privadas ni algoritmos negociables.

Transcripts ASCII exactos, cada elemento separado por LF, incluido LF final:

```text
challenge: BOMB-LICENSE-REQUEST, 1, realm, mac, device_key_sha256, client_nonce
exchange:  BOMB-LICENSE-EXCHANGE, 1, realm, device_id, credential_id, mac,
           device_key_sha256, client_nonce, challenge_id, nonce
```

Las comas/espacios/salto visual anteriores sólo enumeran campos; los bytes
firmados contienen un campo por línea. `realm` procede de configuración confiable
del servidor/equipo, no del body; delimita el ambiente/destino. La firma inicial
se verifica antes de acceder a DB, pero puede repetirse: **no** es la prueba
fresca que habilita entrega. Sólo exchange liga la prueba al nonce servidor.

Challenge devuelve exactamente `id,device_id,credential_id,mac,device_key_sha256,
realm,client_nonce,nonce,issued_at,expires_at`. DB establece expiración exclusiva
a los 120 s. Mismo client_nonce/realm/equipo no consumido y vigente devuelve
el mismo challenge. Tras consumo: 409; tras caducar/prunar puede crearse un
reto nuevo, con nonce/UUID nuevos que exigen una nueva firma de exchange.
No se entrega una licencia con la firma inicial repetida.

Máximo ocho retos por equipo en la ventana de 120 s, incluidos consumidos.
La cuota y el consumo viven en PostgreSQL, no en un Map por instancia.
Retos caducados se podan sólo para el dispositivo que solicita otro; auditoría
se conserva sin secretos. Retención global y límites por IP/WAF antes del
trabajo criptográfico son requisitos operativos aún pendientes antes de abrir
acceso público; esta cuota no es protección global frente a DDoS.

## Respuesta firmada y reloj

Licencia válida: JWS ES256 ya definido en
[contrato compartido](../../bomb-v2/OTA_03_CONTRATO.md), ligado a UUID, credencial,
MAC, huella, revisión y vigencia. Se emite sólo si la concesión actual está
granted y `issued_at <= ahora`, `not_before <= ahora < expires_at`.

Siempre que haya prueba válida y consumo autorizado, se firma además estado:
cabecera canónica `{alg:ES256,typ:bomb-license-status+jwt,kid}`. Payload ordenado:
`v,iss,aud,realm,sub,credential_id,device_key_sha256,mac,license_id,revision,state,
challenge_id,client_nonce,nonce,server_time,license_sha256`.
`v=1`, `iss=bomb-ota`, `aud=bomb-cores3-status`; resto liga concesión, reto y
hora DB. `state`: unlicensed / revoked / expired / not_yet_valid / valid.
Sólo valid lleva licencia y su SHA-256; los demás llevan license_document y
license_sha256 a null. Un HTTP 401/403/409/503 sin estado firmado **no revoca**.

Verificador Node de referencia: keyring local P-256/kid, tipado y JSON/base64
estrictos, binding completo del reto pendiente, revisión mínima y última hora
fiable, monotónico transcurrido desde inicio de solicitud <120 s. Verifica el
hash/licencia y vigencia con cota conservadora `server_time + ceil(elapsed)`:
no revive una licencia vencida en tránsito. El estado firmado no es permiso
offline indefinido. Tras procesar éxito se debe retirar el reto pendiente;
tras reinicio, no restaurarlo desde datos sin autenticar: pedir uno nuevo.
Ese gestor de pendientes, almacenamiento y reloj **aún no existen en CoreS3**.

Revocación observada/revisión se deberán persistir fuera de SD. Sólo una concesión
posterior verificada y durable puede quitar ese bloqueo. La revocación que el
equipo nunca recibió no puede imponerse sin Internet: no prometer revocación
offline instantánea. Se conserva dejar terminar la ronda activa y bloquear
nuevas partidas/rondas, sin STOP remoto a Bomb01 por licencia.

## Autoridad DB y punto de commit

Forward `20260922000200_ota_device_gateway.sql`: `bomb_ota_gateway` NOLOGIN,
NOINHERIT y sin superuser/createrole/createdb/replication/bypassrls. Sin membresías,
acceso a tablas ni RPC administrativos. EXECUTE sólo en `ota_gateway_challenge`
y `ota_gateway_consume`; SECURITY DEFINER, search_path vacío y helper privado.
PUBLIC/anon/authenticated/service_role no ejecutan esos RPC. Claims JWT
configurados por ese rol no le dan acceso a administración.

`ota_private.device_challenges` y `device_license_deliveries`, con RLS y sin
grants de datos al gateway. El gateway es un componente servidor confiable que
verifica firmas antes del RPC: **no distribuir su contraseña al equipo**. Los
RPC por sí solos no verifican ECDSA. Comprometer ese servidor/firmante excede
esta frontera; nunca presentarlo como defensa contra un emisor comprometido.

Las mutaciones usan el mismo lock de inventario que administración. Después de
adquirirlo, un nuevo statement READ COMMITTED obtiene estado actualizado; no
firmar una fila leída antes de esperar una revocación. Consumir → auditoría →
firmar dentro de la transacción → COMMIT → respuesta HTTP. Fallo de firma/auditoría
revierte consumo. Fallo/resultado desconocido de COMMIT no devuelve documentos;
obtener reto nuevo si el anterior aparece consumido. Entrega perdida no renueva
concesión ni incrementa revisión; emite de nuevo el estado vigente tras otro reto.
Una revocación **posterior al commit** puede adelantar a la respuesta por red:
la garantía es estado en ese punto de serialización, no revocación instantánea.

Cada conexión comprueba session_user=current_user=rol esperado, atributos,
membresías, ausencia de CREATE en public y USAGE en ota_private, acceso a tablas public/ota_private y
ejecución de RPC OTA/SECURITY DEFINER públicos distintos de los dos permitidos.
Una concesión accidental de privilegios falla cerrada. Límites locales de
statement 4 s, lock 2 s, idle-in-transaction 5 s; conexión 3 s/query 5 s. Conexión
por operación, cerrada al terminar; Supavisor puede dar pooling externo, sin
prepared statements con nombre. Compatibilidad real con Supavisor sigue pendiente.

## Configuración y recuperación operativa

`OTA_DEVICE_GATEWAY_ENABLED=true` habilita sólo esta ruta; por defecto 503.
Además: `OTA_DEVICE_REALM`, `OTA_LICENSE_SIGNING_KID`, clave PKCS8 P-256 en
`OTA_LICENSE_SIGNING_PRIVATE_KEY`, `OTA_GATEWAY_DATABASE_URL` de rol dedicado,
y opcional `OTA_GATEWAY_DATABASE_CA` con certificado público PEM.
Secretos únicamente en gestor de entorno servidor, no Git/SD/chat/build firmware.
URL sólo Supabase directo puerto 5432 o pooler 5432/6543, DB postgres, usuario
dedicado (en pooler `bomb_ota_gateway.<projectref>`), sin parámetros URL.
TLS siempre rejectUnauthorized:true; no sslmode que lo sobrescriba ni excepción
sin TLS en producción. El socket sin TLS existe sólo como inyección de test.

NOLOGIN es intencional: la migración no fabrica contraseñas. Aprovisionamiento
futuro autorizado habilita LOGIN **en ese mismo rol**, configura contraseña
aleatoria exclusivamente fuera de Git y prueba TLS/atributos. No usar postgres
ni un login privilegiado con SET ROLE para resolver conexión. Revocar LOGIN,
EXECUTE y flag es la vía operativa de cierre; deshabilitar flag no retira SQL.
No se han ejecutado esos pasos en Supabase ni leído credenciales existentes.

Errores: 400 entrada, 401 firma incorrecta, 403 destino no autorizado, 409 reto
usado/inexistente/vencido/no coincidente, 429 cuota, 405/413/415 HTTP, 503 config,
permisos ampliados o indisponibilidad. Mensajes sin datos SQL ni secretos. Una
respuesta perdida o timeout pide reintento controlado; nunca borra activación.
La UI futura conserva origen/WiFi/Estado y explica comunicación, rechazo y vuelta.

## Evidencia y pendientes

`npm test`: **59/59** pruebas Node/proveedor simulado/criptografía con claves sólo en RAM.
`npm run test:db`: PostgreSQL 17.11 aislado, login restringido real, sin TCP ni
secretos externos: bootstrap, rechazo de acceso/roles, ocho consumos simultáneos
(uno exitoso), revocación durante espera del lock, rollback por firma/auditoría,
cuota, nonce/realm/TTL y supervivencia de retos pendientes/consumidos tras reinicio.
El login se habilita sólo en ese clúster desechable; no demuestra TLS/Supabase.
La integración recorre el handler HTTP, rol/SQL reales y firma/verificación;
el transporte inyectado se limita al socket local. Derivas de grants, membresía
y USAGE privado son rechazadas. Revisión independiente sin bloqueos; su sugerencia
de comprobar USAGE privado se incorporó con una prueba real de deriva.

Antes de integración física: Preview autorizado con Auth/PostgREST y rol/TLS
reales, límites perimetrales/retención, recuperación/reemplazo y revocación de
credencial propia (no sólo concesión), claves/CoreS3/SD/RTC y guardas/UI. El alcance
destructivo del reset de fábrica aún necesita decisión del operador. No declarar
cerrado OTA-03 ni LIC-01…06 por pasar estos tests. No nuevos binarios en esta entrega.

Trabajo con `bomb-coder`/`bomb-deep-dive`: coordinador contrato/SQL/criptografía/
integración, Terra medium tests aislados y Terra high revisión independiente.

Fuentes primarias: [TLS node-postgres](https://node-postgres.com/features/ssl),
[conexiones Supabase y roles pooler](https://supabase.com/docs/guides/database/connecting-to-postgres),
[atributos PostgreSQL](https://www.postgresql.org/docs/17/role-attributes.html).
