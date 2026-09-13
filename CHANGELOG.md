# Changelog de NPM Guardian

La fuente única de versión es [`VERSION`](VERSION). Código, API, interfaz,
metadatos OCI e imagen comparten ese valor; no existe un contador de imagen.

## [1.0.5] — soporte de la comunidad

### Added

- Añadido en el acceso y en el pie del panel el enlace de soporte a la comunidad de
  Discord de Unraides.
- La plantilla pública sigue el canal `stable`.

## [1.0.4] — recuperación automática tras un cambio de activo

### Fixed

- Las fechas de ficheros Nginx regenerados ya no pueden bloquear un cambio
  funcional más reciente de la base de NPM.
- Cuando todos los cambios lógicos proceden de un único nodo alcanzable, el
  activo recupera automáticamente su snapshot validado y lo redistribuye al
  resto del clúster, sin reconstruir proxies o certificados a mano.
- La recuperación del activo conserva un backup, aplica el mismo journal
  transaccional y verifica continuamente que el nodo mantiene la VIP.
- La interfaz diferencia una recuperación automática segura de la acción
  destructiva «Imponer este estado».
- El workflow de CI toma la versión de `VERSION` en todos sus pasos y valida también
  `.env.example`, evitando contratos obsoletos al publicar una corrección.
- La comprobación de ausencia de variables en la plantilla usa una condición explícita
  compatible con `errexit`, ShellCheck y `actionlint`.
- La auditoría documenta cuatro usos seguros que Bandit confundía con contraseñas o
  ejecución mediante shell, manteniendo el análisis estricto para el resto del código.

## [1.0.3] — configuración local editable desde el portal

### Fixed

- La sección Configuración permite editar los datos locales que dejaron de
  formar parte de la plantilla: identidad y miembros del nodo, Keepalived,
  acceso al portal y conexión con Nginx Proxy Manager.
- Los tokens y certificados CA se guardan como ficheros privados bajo
  `/datos/secrets`; el portal indica si existen sin devolver su contenido.
- Una instalación anterior basada en variables puede guardar desde el portal y
  migrar su configuración y secretos administrados al volumen persistente.
- Los cambios se aplican reiniciando el proceso dentro del mismo contenedor; no
  se crea ningún contenedor auxiliar.

## [1.0.2] — configuración inicial dentro de la aplicación

### Fixed

- La plantilla Unraid pasa de 32 campos a 5 conexiones Docker: puerto, datos de
  NPM, certificados de NPM, datos de Guardian y socket Docker.
- Un asistente web de primer inicio recoge la topología, Keepalived, el acceso al
  portal y la conexión con NPM; todo queda persistido bajo `/datos`.
- Guardian genera los secretos de sesión y clúster con permisos `0600`. El primer
  nodo entrega un código de incorporación que instala los mismos secretos en los
  demás nodos sin introducirlos en la plantilla ni en variables Docker.
- El token de Keepalived se guarda por separado bajo `/datos/secrets` y nunca se
  incluye en `node.json` ni se devuelve en consultas ordinarias.
- Los despliegues anteriores basados en `NPMG_*` siguen siendo compatibles y
  conservan prioridad, sin añadir contenedores auxiliares.

## [1.0.1] — corrección de arquitectura de despliegue

### Fixed

- NPM Guardian vuelve a ser una aplicación de un único contenedor. El servicio
  principal monta el socket Docker y conserva la lista blanca estricta sobre el
  NPM configurado; se eliminan el sidecar, su red, su token y su segunda plantilla.
- Compose, la plantilla Unraid, el despliegue y la documentación describen la
  misma topología de un solo contenedor y limpian restos de la topología anterior
  únicamente después de validar el nuevo proceso.
- El canal público adopta el nombre definitivo `Ezr43l/npm-guardian-s` y la
  imagen `ghcr.io/ezr43l/npm-guardian-s`, sin renombrar el repositorio privado.

## [1.0.0] — estable, preparada para publicación

Esta sección describe el contenido estable preparado. No afirma que `v1.0.0` esté
desplegada ni publicada: el tag Git se crea tras la CI y la validación del candidato local;
ese tag produce el digest público inmutable, que después se verifica y se despliega
pasivos-primero antes de cerrar la checklist externa.

### Added

- Licencia Apache-2.0 adoptada para código y documentación, incluida en la imagen y declarada
  en OCI; la release pública exige `LICENSE_SPDX=Apache-2.0`.
- Compatibilidad verificada con la imagen oficial NPM `2.15.1` fijada por digest en ARM64 y
  AMD64; el laboratorio espera tanto el PID maestro como una configuración Nginx válida para
  evitar la carrera observada durante el arranque.
- CI y release fijan acciones y herramientas, auditan Bandit en todas las severidades y
  exigen CI previa, ambas arquitecturas, SBOM y procedencia antes de publicar.
- La consulta a Keepalived admite una clave API `status:read` directa o por fichero, la envía
  exclusivamente como Bearer y rechaza valores aptos para inyectar cabeceras.

- Alta disponibilidad portable para un conjunto configurable de NPM, con el
  portador de la IP flotante como única autoridad de escritura.
- Portal completo autenticado en el activo y vista deliberadamente reducida en
  pasivos o cuando la autoridad es desconocida.
- Sincronización programable mediante presets o cron de cinco campos, además de
  comparación previa y una imposición manual explícita.
- Namecheap como integración opcional y desactivada inicialmente. La función
  base de réplica no depende de sus credenciales.
- Login humano delegado en el NPM activo, vinculación por ID estable, sesión
  corta, CSRF, TOTP y códigos de recuperación de un solo uso.
- Favicon e icono de producto PNG de 128 × 128, título **NPM Guardian** en las
  vistas activa y pasiva e instalación verificada del icono en las dos cachés
  de DockerMan de Unraid.
- Modales y notificaciones propios; no se usan diálogos nativos del navegador.

### Consistency and availability

- Quórum por mayoría para el estado sensible del clúster. En la topología de
  tres nodos, activo más un par forman `2/3`; un tercer nodo ausente se informa
  como degradación y se reconcilia al regresar.
- Sin quórum se bloquean el primer login, los cambios de cuenta/2FA/configuración
  y el inicio de una renovación. Las lecturas de salud y el NPM que ya sirve
  tráfico no se detienen por ello.
- Reconciliación por mayoría del contenido lógico de `guardian.json`: `revision`
  y `updated_at` son metadatos y no votos. Una revisión alta presente en un solo
  nodo nunca desplaza al contenido respaldado por quórum.
- Rebase del contenido confirmado por encima de la mayor revisión observada
  (`max + 1`) y réplica obligatoria de ese rebase a mayoría antes de autorizar
  login, cambios sensibles o renovaciones; sin una mayoría inequívoca se falla
  cerrado.
- Bootstrap determinista posterior al *majority-read*: sólo el activo puede
  promover el documento inicial y esa promoción también debe volver a quedar
  fijada en quórum antes de vincular la primera cuenta.
- Reconciliación periódica de configuración y ledger independiente del cron de
  snapshots de NPM.
- Identificadores no reversibles de los secretos compartidos para detectar un
  miembro incompatible antes de aceptar login o estado.
- Fence de membresía: `NPMG_NODES` debe coincidir exactamente con el nodo local
  más `NPMG_PEERS`. La huella estable de esa topología forma parte del esquema 3
  y del AAD de cada escritura interna.
- El esquema 2 sólo se acepta como compatibilidad transitoria durante una
  actualización escalonada y nunca aporta una confirmación válida al quórum de
  la versión 1.
- Heartbeat autenticado cuando el inventario ya coincide. Un pasivo sólo anuncia
  `ready` con base de datos, contenedor Docker, API NPM y sincronía topológica
  reciente verificadas.

### Replication

- Snapshot SQLite mediante la API de backup, `PRAGMA quick_check`, segunda copia
  de contraste y huella estable del resto de artefactos. Si NPM cambia durante
  la captura, se reintenta y finalmente se aborta sin enviar una mezcla.
- Manifiesto exacto con SHA-256, lista blanca de rutas, enlaces simbólicos
  confinados, límite comprimido de 64 MiB, expandido de 512 MiB y máximo de
  elementos.
- Aplicación transaccional en el pasivo con staging durable, `fsync` de archivos
  y directorios y journal `prepared/swapping/swapped/committed`. La decisión de
  recuperación hacia delante queda durable antes del primer `rename`.
- Recuperación al arrancar tras una interrupción, preservando si NPM estaba en
  ejecución. El estado nuevo sólo se conserva si recupera salud; en caso
  contrario se fija primero la decisión inversa, se restaura el anterior y se
  valida su salud. Un rollback incierto falla cerrado y conserva journal y
  rutas anteriores en lugar de arrancar un estado parcial.
- Comprobación posterior de contenedor, SQLite y API NPM antes de confirmar una
  réplica; conservación rotatoria de tres snapshots previos.
- `operacion.json` serializado bajo candado y persistido mediante reemplazo
  atómico con `fsync` de fichero y directorio.

### Certificate renewal

- Margen inicial de 35 días y política configurable de uno a cuatro intentos
  automáticos, dejando el quinto para intervención manual.
- Cuota semanal por conjunto SAN exacto y canónico, no por ID mutable de NPM.
  Los fallos se agregan por identificador DNS; wildcard y apex comparten su
  nombre base para proteger el límite de autorización.
- Ledger monotónico y fusionable que conserva intentos, fallos, estados
  indeterminados y emisiones completadas. Un éxito no borra el consumo semanal.
- Reserva del intento en quórum antes de enviar la petición a NPM. Si la reserva
  no alcanza mayoría, se revierte con una revisión posterior y no se emite.
- Reconciliación de timeouts y respuestas ambiguas sin repetir inmediatamente
  una operación que NPM puede haber completado.
- Verificación del cambio real de PEM y del fingerprint DER servido por todos
  los consumidores TLS activos: proxy hosts, redirecciones y dead hosts.
- Una renovación sólo es completa tras PEM nuevo, TLS correcto, snapshot de NPM
  en quórum y resultado final del ledger en quórum. Los estados intermedios se
  notifican como pendientes y no desencadenan otra emisión.
- Namecheap sólo bloquea los certificados DNS-01 que usan ese proveedor;
  HTTP-01 y otros proveedores siguen su propio flujo.

### Security

- El proceso web ya no recibe `docker.sock`. Un sidecar sin puertos publicados
  aplica autenticación de token, nombre exacto de NPM, inspección saneada,
  `start/stop` y únicamente `nginx -t`/`nginx -s reload`; Compose, Unraid y el
  despliegue remoto usan la misma frontera.
- Ficheros de secretos y CA rechazan enlaces, objetos no regulares y tamaños
  excesivos; los agentes Unraid se abren con `O_NOFOLLOW` y se ejecutan por su
  descriptor estable para cerrar carreras TOCTOU.
- Aperturas remotas limitadas a HTTP(S), framing HTTP estricto, SQL dinámico
  ligado a allowlists y directorios temporales creados mediante `tempfile`.

- Portal seguro por defecto: login y mutaciones requieren un proxy declarado en
  `NPMG_TRUSTED_PROXY_IPS` y un único `X-Forwarded-Proto: https`. El perfil LAN
  por HTTP necesita `NPMG_ALLOW_INSECURE_PORTAL=1` explícito.
- Cookie `HttpOnly`, `SameSite=Strict` y `Secure` en el perfil seguro, HSTS bajo
  HTTPS confiable y duración inicial de 15 minutos, limitada a 5–60.
- API de NPM por HTTPS de forma predeterminada, con esquema, puerto y CA
  configurables. HTTP exige `NPMG_ALLOW_INSECURE_NPM_API=1`.
- API de Keepalived por HTTPS verificable o CA privada. HTTP exige
  `NPMG_ALLOW_INSECURE_KEEPALIVED_API=1`.
- Cada mutación revalida contra `/api/users/me` el token NPM de la sesión, el ID
  vinculado, el rol administrador y el estado habilitado de la cuenta.
- Secretos persistidos con Fernet; configuración, ledger y estado anti-replay
  usan escrituras atómicas, copia válida y comportamiento fail-closed ante
  corrupción.
- Canal interno con claves separadas por HKDF, HMAC-SHA-256, AES-GCM, unión a
  origen/destino/ruta/nonce y protección anti-replay durable.

### Packaging and versioning

- Instalación neutral mediante Compose, plantilla Unraid y despliegue remoto sin
  servidores, rutas, claves ni registros propios del autor.
- Único archivo `VERSION` con `1.0.0`; imagen `npm-guardian:1.0.0`, API y etiqueta
  OCI `1.0.0`, interfaz `v1.0.0` y tag previsto `v1.0.0`.
- Validaciones de versión, salud, imagen y metadatos OCI durante el despliegue;
  actualización del activo al final y conservación del contenedor anterior de
  rollback durante la validación del conjunto, sin retirarlo nodo a nodo.

### Verification

- La versión estable acumula 136 pruebas automáticas superadas en ARM64 y AMD64,
  además de un laboratorio Docker real contra NPM 2.15.1 en ambas arquitecturas.
  Esta evidencia valida el artefacto revisado, pero no afirma que
  exista despliegue estable, tag Git ni publicación de `v1.0.0`.
