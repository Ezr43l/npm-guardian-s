# Compatibilidad con Nginx Proxy Manager

## Matriz de NPM Guardian 1.0.5

| NPM | Estado | Evidencia |
| --- | --- | --- |
| `2.15.1` | soportado y verificado | imagen oficial `jc21/nginx-proxy-manager:2.15.1@sha256:52b2c59994f3d36acfcf70a1626f29734df0ed8c71bacc0269f78b6f939858bb`; laboratorio ARM64 y AMD64 |
| otro `2.15.x` | candidato, no asumido automáticamente | debe superar suite, inventario y réplica física con el socket Docker local antes de añadirse |
| `2.14.x` y anteriores | no soportado para una instalación nueva | fuera de la rama con soporte de seguridad declarada por NPM al validar 1.0.5 |
| futura rama mayor | incompatible hasta revisión explícita | un cambio de esquema desconocido bloquea el inventario y la réplica de forma segura |

La política upstream y las versiones publicadas se comprueban en la
[política de seguridad de NPM](https://github.com/NginxProxyManager/nginx-proxy-manager/security)
y sus [releases oficiales](https://github.com/NginxProxyManager/nginx-proxy-manager/releases).
Guardian no transforma «misma rama» en compatibilidad implícita: la matriz
registra artefactos que se han ejecutado realmente.

## Riesgo upstream observado

El 30 de agosto de 2026, Trivy 0.74.0 detectó vulnerabilidades `HIGH` y
`CRITICAL` con corrección disponible dentro de la imagen oficial exacta de NPM
2.15.1, incluidas dependencias Node y Python. Esos paquetes pertenecen a NPM y
no a la imagen de Guardian; Guardian no los reemplaza ni oculta el resultado.
La imagen propia de Guardian sí mantiene su puerta en cero `HIGH/CRITICAL`.

Hasta que NPM publique una versión estable corregida, una instalación debe
mantener 2.15.1 fijada por digest, limitar la exposición de su interfaz de
administración y vigilar la siguiente release upstream. Cualquier actualización
de NPM exige repetir la matriz completa antes de declararla compatible.

## Qué cubre el laboratorio

Para cada arquitectura de Guardian, el laboratorio crea una red y volúmenes
efímeros, arranca el NPM oficial, espera tanto al PID maestro como a que
`nginx -t` sea válido y prueba:

- inspección del NPM con respuesta saneada, sin `Env` ni mounts;
- `nginx -t` seguido de `nginx -s reload` mediante órdenes exactas;
- parada y arranque del único nombre permitido;
- rechazo de otro contenedor y de rutas de imágenes;
- montaje único de `docker.sock` en NPM Guardian;
- ausencia de órdenes Docker arbitrarias;
- limpieza de contenedores y volúmenes del laboratorio.

La suite adicional valida el esquema SQLite autoritativo, snapshot coherente,
manifiesto, aplicación transaccional, rollback y quórum con dobles controlados.
La prueba de tres hosts Unraid reales complementa esta matriz y queda enlazada
en el laboratorio físico privado: reprodujo corte, réplica degradada, relevo
real de VIP, rejoin y rollback sin cambiar la versión NPM fijada.

## Incorporar un parche nuevo

1. Revisar release notes y política de seguridad upstream.
2. Fijar tag y digest del artefacto candidato; no reutilizar el digest actual.
3. Ejecutar las 136 pruebas en ARM64 y AMD64.
4. Ejecutar el laboratorio Docker en ambas arquitecturas.
5. Probar tres hosts con réplica, failover, nodo aislado, regreso y rollback.
6. Actualizar esta matriz, CI, evidencia y checklist en el mismo cambio.

Si aparece una tabla SQLite nueva, falta una requerida o cambia el contrato de
la API, Guardian debe bloquear la réplica y mostrar incompatibilidad. No se
añade la tabla a una allowlist sin decidir primero si contiene estado
autoritativo, operativo o secretos que requieren tratamiento especial.
