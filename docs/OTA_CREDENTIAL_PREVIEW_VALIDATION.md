# OTA-03 — validación real de credenciales en Development/Preview

Fecha: 2026-09-30. El operador autorizó continuar con Development/Preview después
de conservar las versiones instaladas y publicar sus tags estables. Esta entrega
valida el backend con dispositivos sintéticos; CoreS3 0.2.36 y Bomb01 B01-GAME-13
conservan el firmware instalado. No se cierra la integración física OTA-03.

## Destinos y migraciones

- Supabase existente `boom-manager`, proyecto `cdurakjehpvcwmvsgire`.
- Vercel existente `bomb-v2-ota-api`, runtime Node 24.x; despliegues Preview.
- Primer Preview READY: `https://bomb-v2-ota-k966hrok1-johnosorios-projects.vercel.app`,
  ID `dpl_ANtKHdG4tQWeXPMqV3aZXQ67r1RT`.
- Protección Vercel `all_except_custom_domains` conservada; petición sin acceso
  al Preview devuelve 302. Las pruebas usan `vercel curl` con bypass de transporte
  del operador y JWT Auth del usuario sintético; son controles distintos.

El preflight con TLS verificado confirmó que sólo existía la foundation.
CLI Supabase 2.117.0 ejecutó dry-run y después `db push --linked --skip-vault --yes`
desde el backend canónico. Sin seeds, reset, Vault ni modificación de migraciones
aplicadas. Historial remoto posterior: las cuatro migraciones, seis tablas públicas
y tres privadas; ninguna sin RLS.

| Migración aplicada en este incremento | SHA-256 |
| --- | --- |
| `20260922000100_ota_license_administration.sql` | `614ce47957c7e92652187a9ea587d0cd58ed6c51c343ac3c7839a2452b49c07a` |
| `20260922000200_ota_device_gateway.sql` | `59343ede22e0eb84a678b23855c7becc7358a0fca7346a7c7fa7940c59dd9c92` |
| `20260930000100_ota_credential_recovery.sql` | `07f784dca2d411d1337e12d7bbeb8ed972c589191559dd68c7ac637b492703ce` |

## Diferencias detectadas y corregidas

1. Supabase expone `public.rls_auto_enable()` SECURITY DEFINER con retorno
   `event_trigger`. El control de privilegios la trataba como un RPC invocable y
   rechazaba un rol correctamente restringido. El control excluye funciones de
   eventos no OTA, manteniendo el rechazo de cualquier rutina `ota_*` adicional
   y de los definers normales. Una regresión PostgreSQL verifica que llamar a la
   función de evento con SELECT falla `0A000`, mientras un definer normal o una
   función `ota_*` de evento bloquean el gateway. No se cambiaron grants de la
   función de plataforma. Referencias: [event triggers PostgreSQL](https://www.postgresql.org/docs/17/event-trigger-definition.html)
   y [creación reservada a superusuarios](https://www.postgresql.org/docs/17/sql-createeventtrigger.html).
2. Vercel rechazó el primer despliegue (`dpl_61KEwUNNXt8z2UcyfLsaC2VVifg2`) por
   `exceeded_serverless_functions_per_deployment`, límite 12 del plan actual.
   Los tres handlers de manifiestos se agrupan en `api/releases/[channel].js` y
   su helper pasa a `lib/releases.js`. Se conservan las URL, los manifiestos y
   los binarios; no hubo cambio de plan ni promoción de canal.
3. La revisión independiente detectó que reutilizar el ID del fixture podía
   afectar la credencial de una ejecución anterior. El runner genera un ID de
   dispositivo nuevo por invocación, comprueba lecturas antes de comparar estados
   y falla si no puede retirar la credencial sintética al finalizar.

## Aprovisionamiento y fronteras

`bomb_ota_gateway` recibió LOGIN y contraseña aleatoria exclusivamente para el
backend Development. Conexión real al pooler de sesión 5432, TLS verificado y rol
efectivo propio: sin membresías, atributos administrativos, acceso a tablas,
CREATE en public ni USAGE en ota_private. El runtime conserva su comprobación de
privilegios en cada transacción. Contraseña SQL y firmante PKCS8 P-256 se enviaron
sólo como entorno runtime del Preview, sin valores en argumentos/logs/Git ni
credenciales administrativas del equipo. Realm `bomb-preview-20260930`, kid
`preview-20260930`; no son credenciales de producción ni de los equipos físicos.

Se crearon cuatro usuarios Auth sintéticos confirmados `example.invalid` y dos
ámbitos identificados como prueba. No se envió correo ni se cambiaron opciones de
signup/Auth. Las peticiones administrativas usan JWT del admin/viewer/usuario
externo; la clave server-side sólo interviene localmente en crear/cerrar el fixture.
Esto no aprovisiona un administrador humano ni construye el portal visual.

## Resultado

- `npm test`: **63/63**; adaptadores HTTP/criptografía y compatibilidad de canales.
- PostgreSQL **17.11 local aislado**: SQL/RLS, upgrade, concurrencia, rollback,
  reinicio y regresión de funciones event_trigger; clúster detenido al terminar.
- Primer Preview: **24/24 inventario** con Auth/PostgREST reales: ausencia/bearer
  inválido, ámbitos/viewer, idempotencia/conflictos, actor, RLS, auditoría única,
  concurrencia RPC, 413, exclusiones de fuente y manifiesto legacy.
- Primer Preview: **24/24 credenciales**, más retirada final: approve/grant,
  challenge idempotente, exchange ES256 verificado, replay, retiro de clave,
  rechazo de challenge/exchange pendiente antiguos, reemplazo conservando
  concesión/fechas, clave nueva válida, huella histórica rechazada, CAS obsoleto,
  viewer/foreign denegados sin mutación y reemplazo sobre concesión revocada con
  estado firmado revoked sin licencia. Estado final: concesión y clave revocadas,
  revisión 6; dispositivo sintético `c69bf94e-3a7d-4be1-a6f4-daba558d66a9`.
- **6/6 comprobaciones de rutas**: stable/beta/dev, stable con query channel=dev
  sigue respondiendo stable, desconocido y __proto__ devuelven 404.

Código validado conservado en `1f12037`. El primer Preview se creó sobre base
`8246191` con ese diff aún sin commit; el segundo se creó desde `1f12037` con árbol limpio.

Segundo Preview READY: `https://bomb-v2-ota-2in0u5a33-johnosorios-projects.vercel.app`,
ID `dpl_3omukvx5ZbhiM11VRCNo7MX7BpTq`, igualmente protegido (sin acceso: 302).
**3/3 comprobaciones** de Auth/inventario/auditoría original tras despliegue
independiente, más comparación exacta por API del estado completo de licencia y
credencial (revocadas, revisión 6) contra el primer Preview. Esta prueba acredita
persistencia entre despliegues; no fuerza la expulsión de todas las instancias
calientes ni sustituye el test físico de reinicio.

## Repetición y cierre operativo

`scripts/check-ota-credentials-preview.mjs` requiere la misma configuración privada
y fixture Auth `0600` que `check-ota-preview.mjs`, además de `OTA_DEVICE_REALM`,
`OTA_LICENSE_SIGNING_KID` y **sólo la clave pública** en
`OTA_PREVIEW_SIGNING_PUBLIC_KEY`. Claves privadas del dispositivo sintético y MAC
aleatoria local se generan en RAM. El runner nunca recibe la contraseña gateway
ni la clave privada firmante. No forma parte de `npm test`.

El runner retira la credencial activa por API y conserva ledger, concesión,
recibos y auditoría. No reutiliza IDs de otra ejecución. El coordinador debe
cerrar el fixture Auth: retirar sus membresías, banear usuarios y descartar
contraseñas; no borrar registros auditados ni reactivar fixtures cerrados.

Cierre comprobado: cero membresías de los ámbitos sintéticos, cuatro usuarios
baneados, contraseñas locales descartadas, concesión y credencial actual revocadas
(revisión 6), tres credenciales históricas retiradas. Se conserva evidencia,
sin eliminar inventario, recibos ni auditoría. Gateway y firmante quedan disponibles
sólo en los Previews protegidos; el código mantiene flags apagadas por defecto.
No hay administrador humano habilitado en esta entrega.

Recuperación operativa: deshabilitar el Preview o sus flags cierra el HTTP, pero
no revoca SQL. Para retirar el acceso servidor se debe revocar LOGIN/contraseña
del rol dedicado; preservar siempre historial y corregir con migración forward.
El firmante de pruebas no debe reutilizarse como firmante de producción.

## Alcance pendiente

Faltan administrador humano y vistas del portal; provisión/confirmación física de
huella; cliente CoreS3 P-256/verificador/keyring, almacenamiento protegido,
revisión/estado durable, reloj/RTC, UI y guardas; aceptación física LIC-01…06.
Artefactos firmados, canales, asignación/recibos y actualización/rollback siguen
en OTA-04…08. Los manifiestos legacy siguen stable 0.2.13 y dev 0.2.18-dev;
los tags de las versiones físicas actuales no promocionan esos canales.

La protección de Preview limita esta validación al entorno de desarrollo.
Límites perimetrales/IP, retención global de retos/auditoría y rotación/recuperación
operativa siguen siendo requisitos antes de abrir acceso público. No se ha
validado transporte chunked, fallo real de proveedor, multibomba ni firmware.

Coordinador: destinos, secretos, migraciones, corrección de permisos, integración,
pruebas remotas y Git. Luna low: inventario. Terra medium: runner y empaquetado;
Terra high: revisión independiente. Retrabajo: diferencias reales de Supabase,
límite de funciones y aislamiento entre ejecuciones del runner, recogidos arriba.

[Contrato gateway](OTA_DEVICE_GATEWAY.md), [recuperación](OTA_CREDENTIAL_RECOVERY.md)
y [pendientes](OTA_PENDING_NOTES.md).
