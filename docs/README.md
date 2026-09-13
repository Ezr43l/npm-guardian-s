# NPM Guardian 1.0.6 — índice documental

Las puertas reproducibles de publicación están en
[`RELEASE-CHECKLIST.md`](RELEASE-CHECKLIST.md). Los informes físicos de la
infraestructura privada no forman parte del árbol compartible.

Esta carpeta describe el contrato portable de **NPM Guardian 1.0.6**.
No contiene nombres, direcciones, rutas, dominios ni credenciales de una
instalación concreta.

| Superficie | Identidad de versión |
| --- | --- |
| Fuente normativa | `VERSION` = `1.0.6` |
| Imagen OCI pública futura | `ghcr.io/ezr43l/npm-guardian-s:1.0.6` |
| API y metadatos OCI | `1.0.6` |
| Interfaz | `v1.0.6` |
| Tag Git estable | `v1.0.6` |

No existe una segunda versión para la imagen. El canal compartido usa el tag
exacto `v1.0.6`; su creación depende siempre del checklist, no de una fecha o
promesa incluida en este índice.

## Qué documento leer

| Necesidad | Documento |
| --- | --- |
| Autoridad, quórum, degradación y flujos principales | [Arquitectura](arquitectura.md) |
| Instalación segura, perfil LAN y primer bootstrap | [Instalación y primer arranque](instalacion-primer-arranque.md) |
| Campos Docker y asistente de primer inicio | [Configuración y plantilla](configuracion-plantilla.md) |
| Versiones de NPM verificadas y procedimiento de ampliación | [Compatibilidad NPM](compatibilidad-npm.md) |
| Snapshot, journal, ledger, cuotas y seguridad | [Replicación y seguridad](replicacion-seguridad.md) |
| Rutas HTTP e integraciones externas | [API e integraciones](api-integraciones.md) |
| Operación, degradación, renovación y recuperación | [Runbook](runbook.md) |
| Disciplina de release y reversión | [Desarrollo y versionado](desarrollo-versionado.md) |
| Decisiones defensivas que no deben perderse | [Cicatrices](cicatrices.md) |

## Promesa del producto

El nodo que posee la IP flotante es la única fuente autorizada para operar NPM
y distribuir snapshots. Si una conmutación ocurre antes de la siguiente copia,
el nuevo activo puede recuperar el snapshot estable del único nodo que conserva
todos los cambios lógicos más recientes y después vuelve a distribuirlo. Un
pasivo nunca impone estado por iniciativa propia.

El estado de seguridad de Guardian exige mayoría. En el grupo previsto de tres
nodos, `2/3` permiten continuar en modo degradado y un único nodo bloquea las
operaciones sensibles. La configuración usa revisiones monotónicas; el ledger
de renovación se fusiona conservando toda la cuota observada.

Namecheap es opcional y nace desactivado. La alta disponibilidad y la
sincronización siguen disponibles sin él.

## Fronteras importantes

- Guardian no instala NPM ni mueve la IP flotante.
- No fusiona automáticamente bases NPM con ganadores lógicos repartidos; sólo
  recupera sin intervención cuando existe una fuente única verificable.
- No modifica SQLite para renovar; llama a la API del NPM activo.
- Sólo el activo ofrece el portal autenticado. Los pasivos y la autoridad
  desconocida reciben una interfaz reducida sin acciones.
- La contraseña humana pertenece a NPM; Guardian conserva la identidad
  vinculada, sesión, TOTP y hashes de recuperación.
- Una renovación no es completa sólo porque NPM responda: exige PEM cambiado,
  TLS servido y snapshot más ledger confirmados por quórum.
- La réplica es asíncrona. Tres nodos toleran la indisponibilidad de uno para
  operaciones con mayoría, pero el miembro ausente queda desactualizado hasta
  reconciliarse.

## Estado documental

Los documentos describen el contrato que debe superar la exportación pública. No son un
acta de publicación. Commit, digest, resultados de pruebas, despliegue por nodo
y tag `v1.0.6` se registrarán sólo después de observarlos y verificarlos.
