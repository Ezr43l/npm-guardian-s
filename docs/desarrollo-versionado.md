# Desarrollo y versionado

## Identidad de la versión 1.0.4

NPM Guardian tiene una sola versión de producto. Para la primera versión estable:

| Superficie | Valor |
| --- | --- |
| Archivo `VERSION` | `1.0.4` |
| Etiqueta pública futura | `ghcr.io/ezr43l/npm-guardian-s:1.0.4` |
| API y metadatos OCI | `1.0.4` |
| Interfaz | `v1.0.4` |
| Etiqueta Git prevista | `v1.0.4` |

No existe un contador independiente de imagen. La presencia de `1.0.4` en
`VERSION` identifica la aplicación que se está verificando; no demuestra por sí
sola que el tag Git o la release estable ya existan. Una compilación publicada
nunca debe reutilizar una etiqueta para contenido diferente.

## Convención normativa

El archivo `VERSION` es la fuente de verdad y contiene uno de estos formatos:

```text
MAJOR.MINOR.PATCH
MAJOR.MINOR.PATCH-dN
MAJOR.MINOR.PATCH-rcN
```

Ejemplos válidos:

- Desarrollo: `1.1.0-d1`.
- Candidata a estable: `1.1.0-rc1`.
- Estable: `1.1.0`.

La imagen, la API y las etiquetas OCI usan exactamente el contenido de
`VERSION`, sin prefijo. La interfaz y la etiqueta Git añaden `v`. No se admiten
variantes como `-dev.1`, `-rc.1` ni contadores auxiliares de artefacto.

Se aplica versionado semántico:

- `PATCH`: corrección compatible.
- `MINOR`: funcionalidad compatible.
- `MAJOR`: cambio incompatible en configuración, API, operación o datos.

La API HTTP aún no lleva el número de versión en la ruta. Por ello, sus cambios también forman parte del contrato semántico del producto.

## Estructura relevante

| Ruta | Responsabilidad |
| --- | --- |
| `VERSION` | Versión normativa del producto. |
| `docker/guardian/Dockerfile` | Imagen reproducible y versión embebida. |
| `docker-compose.yml` | Desarrollo y operación por Compose. |
| `.env.example` | Ejemplo portable, sin secretos. |
| `unraid/my-NPM-Guardian.xml` | Plantilla portable para Unraid. |
| `docker/guardian/` | Servicio, interfaz y lógica del producto. |
| `tests/` | Pruebas automáticas. |
| `build-image.sh` y `deploy-guardian.sh` | Automatización de compilación y despliegue. |
| `CHANGELOG.md` | Cambios de la candidata y versiones publicadas. |
| `docs/` | Contrato de instalación, operación y mantenimiento. |

La documentación y las plantillas son parte del producto: una modificación de variables, volúmenes, permisos, rutas o integración debe actualizarlas en el mismo cambio.

## Flujo de una modificación

1. Partir de una rama limpia y registrar el alcance.
2. Cambiar primero el contrato o las pruebas cuando se altere un comportamiento observable.
3. Implementar sin introducir valores propios de una instalación.
4. Ejecutar las comprobaciones proporcionales al cambio.
5. Revisar el diff completo y el inventario de archivos.
6. Actualizar `VERSION`, documentación y notas de cambio cuando corresponda.
7. Crear un único commit identificable para la candidata que se va a compilar.

Nunca se incluyen en Git secretos, copias de `guardian.json`, bases de datos, certificados, claves NPM, tokens de clúster, claves de sesión, credenciales DNS ni artefactos producidos por una instalación.

## Comprobaciones antes de publicar

Como mínimo:

```shell
python -m unittest discover -s tests -v
docker compose config
./build-image.sh
```

Compose declara el mismo contexto de compilación para permitir el arranque desde
una copia nueva aunque GHCR todavía no exista. `build-image.sh` sigue siendo la
puerta explícita para fijar versión, arquitectura y publicación multiarch.

Además, deben validarse cuando resulten aplicables:

- Sintaxis de Python, JavaScript, shell y XML.
- Arranque desde una instalación vacía usando solamente las plantillas públicas.
- Persistencia tras reiniciar el contenedor.
- Detección activa, pasiva y desconocida; el estado desconocido debe fallar cerrado.
- Interfaz completa sólo en el nodo activo e interfaz informativa en los pasivos.
- Inicio de sesión delegado a NPM, CSRF, cierre de sesión y 2FA.
- Acceso inicial seguro por proxy confiable y rechazo `426` del HTTP sensible.
- HTTPS, puerto y CA de NPM y Keepalived, además de los opt-ins LAN negativos.
- Bootstrap del activo, reconciliación con quórum `2/3` y degradación con un
  miembro ausente.
- *Majority-read* por contenido lógico sin `revision`/`updated_at`, rebase
  `max + 1` de huérfanos y fallo cerrado cuando ningún hash alcanza mayoría.
- Fence exacto `NPMG_NODES == NPMG_NODE_NAME + NPMG_PEERS`, huella de membresía
  en esquema 3/AAD y exclusión de ACK de esquema 2 como prueba de quórum.
- Sincronización normal, protección frente a un pasivo más reciente y sincronización forzada.
- Heartbeat autenticado/topológico y `ready` condicionado a DB, Docker, API NPM
  y sincronía reciente.
- Journal con decisión forward durable antes del primer `rename`, rollback con
  salud confirmada y comportamiento fail-closed ante corrupción o `fsync`
  incierto.
- Escritura atómica y sincronizada de `operacion.json`.
- Renovación con cuota SAN exacta, fallos por identificador DNS, comprobación
  del fingerprint TLS y confirmación de snapshot más ledger por quórum.
- Namecheap desactivado y activado.
- Ausencia de `alert`, `confirm` y `prompt` del navegador.
- Título `NPM Guardian`, icono de producto antes del título y PNG 128 × 128 en
  las vistas activa y pasiva y en las dos cachés de DockerMan.
- Ausencia de nombres, direcciones, dominios, rutas y credenciales de una instalación concreta.

Un contenedor en ejecución no basta como prueba. La verificación funcional debe consultar la aplicación por HTTP y contrastar las capacidades que declara.

La versión actual ha superado 136 pruebas automáticas en las imágenes ARM64 y
AMD64 y el laboratorio Docker contra NPM 2.15.1 en ambas arquitecturas. El
número registra esa ejecución concreta: no sustituye las pruebas
operativas ni implica despliegue, tag o publicación.

## Publicación de una versión

El orden operativo es deliberado:

1. Congelar y verificar el commit candidato.
2. Ejecutar pruebas y análisis de portabilidad.
3. Compilar `npm-guardian:<VERSION>` desde ese commit.
4. Publicar la misma imagen en cada registro previsto.
5. Comparar el digest de la imagen en todos los registros; debe ser idéntico.
6. Ejecutar la comprobación previa de cada nodo de destino.
7. Desplegar primero los nodos pasivos, uno a uno, y validar su interfaz reducida,
   huella de membresía, `ready` e icono PNG en ambas cachés.
8. Desplegar al final el nodo activo y validar autenticación, estado, sincronización y servicio HTTPS.
9. Retirar el rollback y los restos de la topología anterior después de validar
   salud, versión e imagen en cada nodo.
10. Ejecutar las pruebas externas de humo y guardar evidencias no sensibles.
11. Crear la etiqueta Git `v<VERSION>` y la publicación asociada sólo cuando el despliegue haya terminado correctamente.
12. Actualizar la documentación operativa compartida con resultados verificados.

Para la versión `1.0.4`, la imagen es `ghcr.io/ezr43l/npm-guardian-s:1.0.4` y la etiqueta Git
prevista es `v1.0.4`. La etiqueta estable no se crea por adelantado y no se
mueve después.

## Evidencias mínimas de publicación

El acta de una publicación debe enlazar o registrar, sin secretos:

- Commit y etiqueta Git exactos.
- Valor del archivo `VERSION`.
- Digest OCI comprobado en cada registro.
- Resultado y fecha de las pruebas automáticas.
- Resultado de la comprobación previa y del despliegue por nodo.
- Respuesta de versión y salud observada desde fuera del contenedor.
- Verificación de rol activo/pasivo y acceso a la interfaz correspondiente.
- Prueba de una sincronización completa o justificación de por qué no procede.
- Incidencias abiertas, mitigaciones y decisión de aceptación.

Este repositorio documenta el contrato, pero no contiene un acta de `v1.0.4` hasta disponer de esas evidencias reales.

## Despliegue y reversión

Antes de actualizar se conserva una imagen anterior identificada por digest, el
contenedor anterior renombrado para rollback y una copia válida de la
configuración. El contenedor se conserva durante la validación completa del
grupo. Si la nueva versión falla:

1. Detener el avance a los nodos restantes.
2. Mantener o recuperar el nodo que siga sirviendo el rol activo de forma válida.
3. Volver a la imagen anterior por digest, no por una etiqueta mutable.
4. Reiniciar y comprobar salud, rol e interfaz.
5. Restaurar datos sólo si existe una incompatibilidad o corrupción demostrada; una reversión de imagen no implica automáticamente restaurar el estado NPM.
6. Registrar la causa y añadir una prueba de regresión antes de una nueva candidata.

No se debe forzar una sincronización como mecanismo de reversión sin confirmar antes qué nodo contiene la copia correcta.

## Cambios incompatibles

Una modificación es incompatible si requiere al menos una de estas acciones:

- Cambiar manualmente una variable obligatoria o el formato de `guardian.json`.
- Alterar el significado de una ruta o respuesta de la API.
- Modificar el formato del paquete de replicación.
- Eliminar una capacidad o integración sin una transición compatible.
- Impedir el retorno a la versión estable anterior sin migración.

Cada cambio incompatible necesita versión mayor, plan de migración, copia de seguridad, procedimiento de reversión y prueba desde la versión estable previa.
