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

## Publicar un firmware de prueba

Desde este directorio:

```sh
./scripts/publish_firmware.sh ../../.pio/build/core_s3/firmware.bin 0.2.2
```

El script copia el binario, calcula SHA-256 y actualiza `release.json`. Después
se despliega este directorio como proyecto Vercel.

El firmware del dispositivo valida tamaño y SHA-256 antes de escribir la
partición OTA. La URL HTTPS del ejemplo usa un cliente TLS sin pinning solo
para desarrollo; producción debe incorporar una CA o pin de certificado.
