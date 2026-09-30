# Release OTA CoreS3 0.2.40

Preparación 2026-10-01 sobre master `1a31a57`, base del backend público de
2026-09-19. No incorpora `feat/ota-phase1-foundation` ni sus APIs/migraciones.

Artefacto conservado, sin recompilar: firmware `ebb39f7`, tag
`checkpoint/ux-ota-presentation-2026-09-30`, entorno core_s3/canal stable.
Origen: `../bomb-v2/.pio/candidates/0.2.40-ota-presentation/firmware.bin`.
Tamaño 1 447 824 B; SHA-256
`c34073a1218f6b59af2bab84d925171dfa5231e87a0e0331ef3a1f3ca60513a5`.
Destino `/firmware/bomb-manager-0.2.40.bin`; manifiesto `release.json`.
Build sin provisión de clave de radio ni token de recuperación PIN.

Cambio: presentación OTA distingue canal, instalada, publicada y comparación;
hereda navegación Sistema/PIN de 0.2.39. Equipo actual 0.2.39 cargado por USB.
La instalación se iniciará manualmente por OTA desde Equipo → Actualizaciones,
sin escritura USB. SD y Wi-Fi requeridos; ninguna partida activa.

Pruebas firmware: `../bomb-v2/hardware/validation/ota-presentation-0.2.40.md`.
El test del manifiesto verifica tamaño y hash contra el artefacto real. La exclusión
Vercel evita enviar entorno local, config, documentación o tests.

Estado de preparación: no desplegado ni instalado. Publicar STABLE afectará al
manifiesto compartido de los CoreS3 que consulten ese canal; cada instalación
requiere acción del operador. El nombre STABLE no acredita aceptación física
completa ni OTA gestionado/autenticado. Las guardas rechazan versiones anteriores;
volver el manifiesto a 0.2.13 no rebaja un equipo actualizado.

Base de reversión del servicio: despliegue público anterior
`dpl_Frha9un7dngwCTjKuopsda6QmFBt`, URL
`https://bomb-v2-ota-hlgd1ecea-johnosorios-projects.vercel.app`.
No ejecutar rollback ni cambiar aliases como prueba. La confirmación automática
de arranque no sustituye aceptación visual ni prueba física de rollback.
