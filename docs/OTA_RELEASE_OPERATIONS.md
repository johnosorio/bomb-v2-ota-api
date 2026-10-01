# Publicación reproducible: firmware y cambios sólo backend

Incremento local de 2026-10-01. Las pruebas usan Git temporal y Vercel/HTTP
sintéticos. Este documento no acredita un despliegue de este runner ni autoriza
promover STABLE, modificar Auth, migrar la base o instalar firmware.

## Destino y entorno

Usar el repositorio canónico `bomb-v2-ota-api`. El target contiene únicamente
`project_id`, `team_id`, `public_url` (origen HTTPS), `previous_deployment` y
`base_ref` (ref completa de un tag inmutable que identifica el backend público).
La procedencia del deployment público debe coincidir con ese commit. Un cambio
de alias/base exige otro target revisado; no se resuelve forzando un reintento.

El despliegue candidato usa Production con `--skip-domain`, conservando el alias
público hasta promoción. Antes de intentar desplegar se consultan los nombres y
destinos de variables persistentes del proyecto con la API Vercel y `decrypt=false`.
Los siete nombres requeridos para cualquier proyecto son:

- `OTA_ADMIN_ENABLED`
- `OTA_PIN_RECOVERY_ENABLED`
- `OTA_DEVICE_REALM`
- `OTA_GATEWAY_DATABASE_URL`
- `OTA_GATEWAY_DATABASE_CA`
- `SUPABASE_URL`
- `SUPABASE_PUBLISHABLE_KEY`

Todos deben incluir destino `production`. El campo opcional `required_env`
declara exactamente este mismo conjunto; no reduce requisitos. Se comprueba
presencia, no validez del contenido ni conectividad con Auth/DB. No se copian
valores al paquete, target, estado o argumentos; un error de metadata se sanea.
No usar overrides temporales para completar un entorno incompleto.

Si Vercel protege el candidato, aportar `BOMB_OTA_CANDIDATE_BYPASS` al proceso de
verificación/promoción mediante el mecanismo privado del operador. Nunca poner
su valor en Git, target, descriptor o argumentos. El runner elimina esa variable
de todos los subprocesos Git/Vercel y sólo la usa en el header
`x-vercel-protection-bypass` contra el origen HTTPS exacto del candidato.
No sigue redirecciones. Verificar el alias público siempre es anónimo, incluso
si la variable sigue presente en el proceso. Un error del candidato no imprime
respuestas ni detalles que puedan contener el secreto.

## Recorrido sólo backend

Preparar y revisar un commit/tag de código backend que descienda del tag público.
Debe conservar por ruta, modo, tamaño y SHA-256 todos los `release*.json`,
`releases/**` y `public/firmware/**`. Cualquier modificación, alta o eliminación
de esos archivos se rechaza antes de crear refs de release o desplegar. Los
manifiestos públicos admitidos siguen siendo stable/beta/dev; ampliar canales
requiere revisar el contrato de empaquetado/verificación.

Los siguientes comandos son etapas manuales, no un script para ejecutar de una
vez. Sustituir los marcadores por el commit, tag y target revisados:

```sh
node scripts/ota-release.mjs plan-backend --commit SHA40 --source-tag TAG --target TARGET.json
node scripts/ota-release.mjs prepare-backend --commit SHA40 --source-tag TAG --target TARGET.json
node scripts/ota-release.mjs status --id backend-SHA40
node scripts/ota-release.mjs git --id backend-SHA40 --authorize INPUT_HASH
node scripts/ota-release.mjs deploy --id backend-SHA40 --authorize INPUT_HASH
node scripts/ota-release.mjs verify-candidate --id backend-SHA40
node scripts/ota-release.mjs promote --id backend-SHA40 --authorize INPUT_HASH
node scripts/ota-release.mjs verify-public --id backend-SHA40
```

`git` verifica los tags público y fuente en el remoto, crea refs separadas
`release/backend-SHA40` y `backend/SHA40` apuntando al commit existente, sin crear
versión OTA, recompilar ni cambiar rama/índice de trabajo. Se publica por Git
antes de desplegar. `--authorize` vincula el comando al resumen revisado; no
sustituye autorización humana o permisos del entorno.

La verificación compara todos los campos de los manifiestos servidos, incluida
compatibilidad de catálogo, y permite normalizar únicamente `firmware_url` de
ruta relativa a URL absoluta del mismo origen y ruta exacta. Descarga y verifica
TODOS los binarios públicos preservados, incluidos históricos. Cada petición
tiene un plazo total para cabeceras/cuerpo y lectura acotada antes de acumular
bytes. No se solicita una instalación ni se admite `accept` para este modo.

La base actual incluye un marcador beta inactivo (`0.0.0`, tamaño 0, SHA de
marcador) sin binario. Se admite únicamente su contenido heredado exacto y se
compara también remotamente; no se inventa el binario ni se habilita beta.
Los manifiestos activos deben referenciar un artefacto preservado válido.

## Recorrido firmware

Conservar binario/procedencia de build limpio, versión nueva funcional y tag
fuente verificado. El recorrido anterior sigue disponible:

```sh
node scripts/ota-release.mjs describe --provenance FILE --artifact BIN --source-tag TAG --base COMMIT --build-evidence REPO_PATH --test-evidence REPO_PATH --out DESCRIPTOR.json
node scripts/ota-release.mjs plan --descriptor DESCRIPTOR.json --target TARGET.json
node scripts/ota-release.mjs prepare --descriptor DESCRIPTOR.json --target TARGET.json
```

Continuar `status`, `git`, `deploy`, `verify-candidate`, `promote`, `verify-public`
con el ID `CHANNEL-X.Y.Z`, usando el `INPUT_HASH` de ese resumen para las acciones
que lo requieren. La publicación no instala el firmware. `accept` sólo registra
comprobaciones físicas explícitas del operador; un build o HTTP 200 no las acredita.

## Resultado incierto y recuperación

- Si se pierde la respuesta de `deploy`, usar `reconcile --id ID --deployment dpl_ID`.
  Contrasta proyecto, commit y metadata del candidato; nunca crea otro deployment.
- Si se pierde la respuesta de promoción, repetir verificación pública o la
  promoción reconciliada: si el alias ya apunta al mismo candidato, sólo verifica.
  No se repite a ciegas una promoción incierta.
- `cancel --id ID --authorize INPUT_HASH` sólo pausa/libera el lock antes de una
  promoción confirmada o incierta; no revierte una publicación ni toca equipos.
- Un lock local/remoto ajeno no se roba automáticamente. Inspeccionar propietario
  y estado antes de resolverlo. Nunca usar force-push para resolver un conflicto.

Validación local: suite Node del backend, fixtures de conservación de Git,
rechazos OTA, pérdida de respuesta/reconciliación, bypass/origen/secretos y límites
de descarga. Quedan pendientes el primer recorrido real con entorno persistente,
candidato protegido y verificación pública, y la aceptación física independiente.

Fuentes primarias: [Vercel API](https://vercel.com/docs/rest-api),
[bypass de protección](https://vercel.com/docs/deployment-protection/methods-to-bypass-deployment-protection).
