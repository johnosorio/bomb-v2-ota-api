# OTA Dummy API

Servicio mínimo para probar el contrato de actualización remota del Bomb
Manager en Vercel.

## Contrato

`GET /api/releases/stable` devuelve:

```json
{
  "product": "bomb-manager",
  "channel": "stable",
  "version": "0.2.1",
  "firmware_url": "https://.../firmware/bomb-manager-0.2.1.bin",
  "sha256": "64 caracteres hexadecimales",
  "size": 856000
}
```

El binario se sirve como archivo estático desde `public/firmware/`. Vercel no
debe considerarse almacenamiento persistente para producción; este directorio
solo permite validar el flujo. La migración posterior debe cambiar únicamente
el origen del binario a S3, Cloudflare R2 o un servicio equivalente.

## Registro provisional de dispositivos

`POST /api/devices` registra o actualiza la identidad técnica de un dispositivo
y `GET /api/devices` lista los dispositivos conocidos. También se puede
consultar uno con `GET /api/devices?id=bm-cores3-000001`. Esta implementación
usa memoria de proceso únicamente para validar el contrato; los datos se
perderán cuando Vercel recicle la función. La siguiente versión debe usar una
base de datos persistente y autenticación del establecimiento.

## Autorización comercial de demo

Para probar el CoreS3, esta instancia incorpora un fixture inmutable del
establecimiento `01` y su licencia:

- 1 bomba autorizada.
- Solo permite `standalone-demo`.
- `origin: DEMO` y firma ficticia; no representa una licencia comercial.
- El JSON declara `schema_version: 1`; campos: establecimiento, estado
  vigente, licencia, expiración, capacidad, bombas autorizadas, juegos,
  origen y firma demo.
- `GET /api/authorization`, `GET /api/establishments` y
  `GET /api/licenses` son solo lectura; no se permiten escrituras públicas.

El fixture va empaquetado en el despliegue, por lo que sigue disponible tras
un cold start de Vercel y no depende de la memoria efímera de una Function. No
es una base de datos ni un sistema de licencias administrable. Antes de operar
con clientes hay que conectar almacenamiento persistente, autenticar las rutas
administrativas y reemplazar la firma ficticia por autorización criptográfica.

## Ciclo de vida de dispositivos

La API separa el estado de conexión (`status`) del estado de gestión
(`lifecycle_state`). Los estados son `DESCUBIERTO`, `PENDIENTE_DE_AUTORIZAR`,
`VINCULADO`, `DISPONIBLE`, `RESERVADO`, `EN_JUEGO`, `MANTENIMIENTO` y
`RETIRADO`. Las transiciones inválidas responden HTTP 409.

`POST /api/devices` conserva la identidad por `device_id`, `chip_id` y
`wifi_mac`; repetirlo con el mismo `device_id` es un heartbeat. La detección no
autoriza automáticamente una bomba. `PATCH /api/devices` acepta `link`,
`authorize`, `unlink`, `transfer`, `replace`, `retire` o un
`lifecycle_state` explícito. Los cambios quedan en `lifecycle_history` y en
`GET /api/audit`. No se puede desvincular, transferir ni reemplazar un equipo
`RESERVADO` o `EN_JUEGO`. Esta API sigue usando memoria provisional y requiere
base de datos y autenticación antes de producción.

## Publicar un firmware de prueba

Desde este directorio:

```sh
./scripts/publish_firmware.sh ../../.pio/build/core_s3/firmware.bin 0.2.2
```

El script copia el binario, calcula SHA-256 y actualiza `release.json`. Después
se despliega este directorio como proyecto Vercel.

El firmware del dispositivo valida tamaño y SHA-256 antes de escribir la
partición OTA. El CoreS3 usa HTTPS y el bundle de certificados incluido en
ESP-IDF para validar el servidor. La firma del manifiesto y la autorización de
canales quedan como pasos de endurecimiento para producción.
