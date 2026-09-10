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
