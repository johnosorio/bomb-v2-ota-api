# Panel administrativo OTA

Primera entrega, 2026-10-01. Amplía `/admin/` sobre Auth, inventario y RPCs
existentes. No añade migraciones, dependencias ni funciones Vercel; tampoco
modifica firmware, manifiestos o binarios. El CoreS3 funcional conserva 0.2.45.

## Recorridos disponibles

- Acceso por cuenta Supabase, invitación y recuperación de contraseña del portal.
  Token sólo en memoria; sin refresh token persistido. Una recuperación de
  contraseña exige iniciar sesión de nuevo. Correo/callback reales requieren
  aceptación del operador; las pruebas locales simulan Auth.
- Dispositivos: ámbitos de la cuenta, rol admin/viewer, paginación y registro
  confirmado. Registro no acredita posesión, conexión o versión instalada.
- Ficha: identidad pública, credencial activa/retirada, concesión y fechas.
  `granted` se distingue de vencimiento/concesión futura según reloj del navegador;
  la vigencia mostrada es informativa, no concede permiso al dispositivo.
- Acciones admin: vincular identidad contrastada con equipo, conceder/renovar
  fechas explícitas, revocar licencia, retirar o reemplazar credencial con motivo.
  No se concede una licencia automáticamente ni se genera una clave en el portal.
- PIN: conserva comparación de código, autorización y rechazo existentes.
  La lista procede del RPC que filtra solicitudes a ámbitos administrables.
- Versiones OTA: consulta por canal, marcador beta inactivo y error por canal.
  No cambia releases ni afirma instalación/salud del dispositivo.

Cada escritura tiene preparación y confirmación. Los datos se insertan en DOM
como texto. Los roles de UI no son autoridad: APIs/RPCs verifican JWT, membresía,
rol y revisión esperada en cada operación. No se usan las rutas demo en memoria.

## Reintentos y navegación

Un timeout/503 de escritura conserva UUID/cuerpo en memoria y ofrece reintento
exacto. No permite salir del diálogo mientras el resultado sea incierto y avisa
al intentar recargar/cerrar. No persiste comandos ni tokens en almacenamiento del
navegador: si se fuerza el cierre, hay que volver a consultar el estado antes de
preparar otra decisión; no se promete recuperar el UUID tras perder la página.

Un 409 no actualiza la revisión ni reintenta automáticamente. Volver consulta
el estado y una nueva decisión exige otra confirmación. Tras POST confirmado,
si GET falla, el reintento sólo consulta estado. Un recibo histórico nunca se
pinta como estado actual. Cerrar sesión/401 borra la sesión y el estado en memoria.

## Extensión de lectura del inventario

`GET /api/ota/devices?action=context&limit=50&offset=0` devuelve
`{schema_version:1,scopes:[{id,name,role}],limit,offset}`.
Mismo flag `OTA_ADMIN_ENABLED`, configuración pública y JWT/RLS que inventario.
Sólo membresías del usuario verificado, join FK a ámbitos, campos filtrados,
orden por `scope_id`, límites 1…100 y offset 0…1000000. Query estricta;
POST con query se rechaza sin escritura. GET/POST de inventario mantienen
su contrato. No hay autoalta de ámbitos, usuarios o permisos.

La consulta de licencias requiere `OTA_LICENSE_ADMIN_ENABLED=true` y sus
migraciones existentes. Un error/configuración deshabilitada muestra reintento;
no se convierte en licencia inexistente. La configuración Auth del portal
conserva el endpoint PIN vigente y su feature flag.

## Validación y despliegue

Pruebas de contexto verifican Auth, filtros, límites, unión/roles inválidos,
respuestas saneadas y rechazo de POST con query. Pruebas VM ejecutan el script
real con DOM simulado: recovery previo, viewer, errores de lectura, confirmación,
replay exacto, CAS, refresco tras escritura y texto no interpretado como HTML.
Revisión independiente de permisos/errores por `bomb_reviewer`; coordinador
integra y ejecuta suite canónica. Navegador local con endpoints sintéticos para
navegación, ficha, confirmación, PIN y diseño móvil; no muta datos reales.

El nuevo join PostgREST y la UI con Auth real requieren comprobación en Preview
antes de publicar. Mantener manifiestos y firmware idénticos con el recorrido
[sólo backend](OTA_RELEASE_OPERATIONS.md). El panel puede convivir con 0.2.45
sin otra carga física.

Fuera de esta entrega: asignaciones/recibos OTA, auditoría navegable, CRUD de
usuarios/ámbitos, traslado/edición/baja de dispositivos y publicación desde web.
Las APIs demo no se utilizan para simular estas capacidades.

Validación del candidato local: **137/137** entradas de la suite `npm test`,
**20/20** pruebas del portal (Auth + administración) y **19/19** de
contexto/inventario. `git diff --check` y enlaces locales correctos.
Chrome de prueba: listado/ficha, preparación y cancelación de licencia,
entrada/salida de autorización PIN, tres canales y viewport 390×844 sin
scroll horizontal. Capturas sintéticas conservadas bajo
`/private/tmp/bomb-web-admin/`. No se utilizaron cuentas ni secretos reales.
Publicación y validación Auth/PostgREST remotas todavía pendientes.
