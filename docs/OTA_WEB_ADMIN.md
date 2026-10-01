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

La lectura del nuevo join PostgREST y la UI con una sesión humana real
requieren aceptación del operador; los controles HTTP comprobados al publicar
se detallan abajo. Mantener manifiestos y firmware idénticos con el recorrido
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
En el corte de validación local, publicación y Auth/PostgREST remotos seguían
pendientes; la publicación posterior se registra a continuación.

## Publicación autorizada — 2026-10-01

Operador: «lanzalo para verlo en la web». Fuente `7f409746db0fa0125fc734608bac719aa08c3d88`,
checkpoint `checkpoint/web-admin-2026-10-01`, referencias fuente y release
verificadas en GitHub antes de desplegar. Release sólo backend
`backend-7f409746db0fa0125fc734608bac719aa08c3d88`.

Candidato `dpl_DsQ9kda4S2tHPepvYFmJd24vrxpm`, promovido a
https://bomb-v2-ota-api.vercel.app/admin/ después de verificar manifiestos y
bytes. Alias y todos los binarios comprobados públicamente sin bypass a las
20:35:30 UTC. Los 22 archivos OTA conservan bytes/modos de la base pública
`4bcfb024`; no se publica firmware nuevo (STABLE sigue 0.2.44; el equipo tiene
0.2.45 por USB). No se modifican cuentas, licencias, credenciales ni hardware.

Las ocho variables necesarias se guardaron en Production del proyecto Vercel
existente mediante stdin privado; antes sólo se suministraban por despliegue.
Incluyen el flag de administración de licencias. Secretos fuera de Git/logs;
la base sigue siendo Development, no producción comercial.

Verificación del candidato y pública: HTML/JS/CSS idénticos al commit, HTTP200,
CSP y no-store; configuración Auth esperada HTTP200; inventario, PIN y licencias
rechazan falta de sesión con 401; contexto rechaza JWT inválido con 401 y POST
con query con 400. La comprobación real de lectura de ámbitos/roles mediante
una sesión humana queda para el operador al entrar; esos recorridos están
probados con Auth/PostgREST simulados, no se afirma un login humano remoto.
La recuperación por correo real sigue pendiente.

Estado durable del runner en `.ota-release/backend-7f409746db0fa0125fc734608bac719aa08c3d88/`;
evidencias HTTP saneadas en `/private/tmp/bomb-web-admin/`. El runner general
completó prepare → Git → deploy → verify → promote con configuración persistente
y bypass existente limitado al candidato; liberó el lock de proyecto al cerrar.

## Ajuste de dispositivos y licencia de prueba — 2026-10-01

Tras aceptación del operador de la navegación real: grupo único como contexto
no seleccionable, inventario en tabla con registrar/actualizar juntos, ficha
separada con licencia, fechas, identidad y explicación del control de vigencia.
La demo legacy no se representa como licencia canónica. CoreS3 0.2.45 muestra
la demo pero no aplica la política firmada al control de partidas; esta
integración sigue pendiente y la ficha lo declara explícitamente.

El operador solicitó 90 días desde hoy para el CoreS3 actual. Concesión aplicada
desde su sesión humana del portal al equipo bm-cores3-E3F61B44, revisión 0 → 1,
del 2026-10-01 00:00 al 2026-12-30 00:00 Europe/Madrid. La lectura posterior
confirmó concesión dentro de vigencia y credencial activa. No se cambiaron
credenciales, firmware ni la demo legacy. El contrato almacena fechas y estado,
no un tipo comercial «prueba». Esto acredita sesión humana, contexto real,
lectura de inventario/licencia y concesión confirmada; no activación en firmware.

Validación del ajuste: 25/25 pruebas del portal, revisión independiente sin
hallazgos; Chrome local con datos sintéticos, vistas de escritorio y móvil
390px sin desbordamiento horizontal. Suite canónica completa: **142/142**.

Ajuste publicado desde `368bc8b5a58d415d1b7fcc69279dd8e4a8dc1021`, checkpoint
`checkpoint/web-devices-2026-10-01`, deployment
`dpl_C6ynWNtDm4RVYTMoGEfsibpjz1zi`. Alias público y los 22 archivos OTA
verificados el 2026-10-01 a las 20:53:31 UTC. HTML/JS/CSS idénticos al commit,
CSP/no-store y controles de sesión confirmados en candidato y alias público.
Estado durable: `.ota-release/backend-368bc8b5a58d415d1b7fcc69279dd8e4a8dc1021/`.
Evidencias saneadas y capturas sintéticas: `/private/tmp/bomb-web-ux/`.

Delegación acotada: inventario de firmware por bomb_explorer (Luna, low),
pruebas por bomb_backend (Terra, medium) y revisión por bomb_reviewer (Terra,
high). Coordinador integró, verificó la suite, concedió mediante sesión humana
y publicó. La revisión no detectó regresiones; la comprobación visual ajustó
alineación de acciones y separación de la ruta de regreso.
