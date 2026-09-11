# Replicación y seguridad

## Autoridad y quórum

El portador confirmado de la IP flotante es el único emisor ordinario. Un
receptor sólo aplica datos cuando se reconoce pasivo y el origen firmado coincide
con el activo observado.

El estado sensible de Guardian usa mayoría:

| Miembros | Quórum | Tolerancia |
| --- | --- | --- |
| 1 | 1 | sin redundancia |
| 2 | 2 | ninguna ausencia |
| 3 | 2 | un miembro ausente |

En tres nodos, activo más un pasivo pueden confirmar una operación con
`ok=true`, `complete=false`, `acknowledged=2`, `quorum=2`. El tercer nodo queda
degradado y debe converger al regresar. Con sólo el activo, login, cambios
sensibles y renovaciones se bloquean; no se detiene el NPM que ya sirve tráfico.

La mayoría sólo es válida dentro de una membresía idéntica. `NPMG_NODES` debe
coincidir exactamente con `NPMG_NODE_NAME` más `NPMG_PEERS` en cada servidor. La
huella estable de esos nombres cerca las escrituras internas y evita que dos
topologías distintas calculen mayorías incompatibles.

## Comparación previa de NPM

El inventario de `certificate` y `proxy_host` ofrece identificador, marca de
modificación, borrado y huella de contenido. Las tablas autoritativas restantes
se comparan por huella agregada de esquema y filas, incluidas cuentas, permisos,
listas de acceso, redirecciones, dead hosts, streams, ajustes y migraciones.

Campos volátiles no deciden la igualdad. Una tabla requerida ausente o una tabla
autoritaria desconocida bloquean la comparación. Un nodo sin respuesta produce
`comparacion_completa=false`; nunca se interpreta como «no tiene el dato».

La sincronización normal separa el estado lógico de SQLite de los artefactos
regenerables. Si todos los cambios lógicos más recientes pertenecen a un único
nodo, éste es la fuente coherente aunque otro miembro tenga un fichero Nginx con
un `mtime` posterior. Tras una conmutación, el activo puede recuperar de esa
fuente un snapshot estable, aplicarlo transaccionalmente y redistribuirlo.

La operación se niega si los cambios lógicos tienen ganadores repartidos, existe
un empate ambiguo, falta algún nodo para confirmar la decisión o sólo difieren
artefactos sin un cambio lógico que identifique su origen. `forzar=true` omite
esa defensa y reemplaza el conjunto administrado completo; requiere decisión
humana y respaldo.

## Captura coherente

El snapshot incluye:

- `data/database.sqlite`, `keys.json`, `nginx/`, `custom_ssl/` y `access/`;
- `letsencrypt/live/`, `archive/`, `renewal/`, `renewal-hooks/`, `accounts/`,
  `credentials/`.

No incluye logs, copias `.bak`, nombres de respaldo ni restos de editor.

El activo:

1. calcula una huella del árbol no SQLite;
2. crea SQLite mediante la API de backup;
3. ejecuta `PRAGMA quick_check`;
4. copia Nginx y Certbot conservando enlaces;
5. vuelve a calcular la huella de artefactos;
6. crea una segunda copia SQLite y compara su SHA-256 con la empaquetada;
7. acepta la captura sólo si ambos intervalos son estables;
8. reintenta hasta tres veces y aborta si NPM sigue cambiando;
9. genera un manifiesto exacto de tipos, tamaños, destinos y SHA-256.

Así no se envía una mezcla conocida de dos instantes. Sigue siendo un snapshot
asíncrono: los cambios posteriores pertenecen a la siguiente ejecución.

## Validación del paquete

Antes de detener NPM, el pasivo exige:

- como máximo 64 MiB comprimidos y 512 MiB expandidos;
- como máximo 20 000 miembros y manifiesto de hasta 4 MiB;
- un único `manifest.json` y una SQLite presente;
- sólo rutas bajo `data/` y `letsencrypt/`;
- ninguna ruta absoluta, `..`, dispositivo ni tipo especial;
- enlaces simbólicos que resuelvan dentro del árbol permitido;
- coincidencia exacta entre archivos extraídos y manifiesto;
- SHA-256, tamaño y tipo correctos;
- `PRAGMA quick_check` correcto en la SQLite recibida.

El paquete viaja dentro de un sobre AES-GCM; la validación anterior protege
además contra contenido válido criptográficamente pero estructuralmente hostil.

## Aplicación transaccional y journal

El receptor requiere que el contenedor NPM exista y esté en ejecución. Prepara
las rutas nuevas sin publicar, hace `fsync` de archivos y directorios y escribe
`/datos/replica-transaction.json` antes de detener NPM. Justo antes del primer
`rename` fija durablemente `swapping` con recuperación hacia delante: un corte
no puede dejar rutas publicadas sin una decisión recuperable.

El journal conserva:

- fase `prepared`, `swapping`, `swapped` o `committed`;
- cada ruta original, nueva y anterior;
- si el destino existía;
- `was_running`, para restaurar el estado de ejecución.

La sustitución usa `os.replace` por cada parte y sincroniza el directorio tras
cambiar nombres. NPM se arranca y la operación sólo se compromete después de
comprobar:

- contenedor en ejecución;
- SQLite local con `quick_check` correcto;
- API NPM alcanzable con el mismo esquema, puerto y CA del cliente real.

Si algo falla antes del commit, se restauran las rutas anteriores y se vuelve a
comprobar salud. Si el rollback tampoco puede demostrarse, Guardian falla
cerrado: deja NPM detenido y conserva journal y `.old` para no servir un estado
parcial.

Al arrancar, Guardian procesa el journal antes de servir el portal:

- `prepared`: limpia staging y vuelve a iniciar NPM si estaba activo;
- `swapping` o `swapped` con decisión hacia delante: completa los renames y
  valida contenedor, SQLite y API; si el estado nuevo no queda sano, persiste
  primero la decisión contraria, restaura y valida el estado anterior;
- `swapping` o `swapped` con rollback decidido: infiere cada rename inverso,
  restaura y valida salud;
- `committed`: termina únicamente la limpieza pendiente;
- journal corrupto o con rutas fuera de NPM: bloquea el arranque.

Se conservan los tres snapshots previos más recientes. El journal no sustituye
un respaldo externo, pero sí cubre la ventana de interrupción local.

## Configuración monotónica

`guardian.json` contiene calendario, Namecheap, política de renovación, acceso
técnico NPM, cuenta vinculada y 2FA. Los secretos viajan ya cifrados.

Reglas:

- documento inicial determinista en revisión `1`;
- la promoción a revisión `2` sólo ocurre después de confirmar ese contenido
  inicial por mayoría y también debe replicarse a quórum;
- el voto se calcula sobre el contenido lógico completo, excluyendo únicamente
  `revision` y `updated_at`;
- sólo se adopta un hash lógico presente en al menos el quórum de miembros;
- una revisión mayor aislada es un huérfano, no evidencia de commit;
- el contenido ganador se rebasa por encima de la mayor revisión observada
  (`max + 1`) cuando hace falta cercar un huérfano;
- ese rebase debe alcanzar mayoría antes de autorizar otra operación sensible;
- sin una única mayoría válida se falla cerrado;
- primario corrupto: recuperación desde copia válida;
- primario y copia corruptos: no se regenera silenciosamente, se bloquea.

Antes del login o una mutación sensible, el activo consulta el estado de los
pares y ejecuta este *majority-read*. Después vuelve a distribuir el contenido
confirmado. Un bucle independiente repite la convergencia aunque el cron NPM
esté desactivado. `revision` conserva orden causal para receptores monotónicos,
pero nunca cuenta como voto.

Los paquetes de configuración incluyen identificadores no reversibles de los
secretos. Un miembro con secreto de sesión o token de clúster diferente se
marca incompatible y no aporta quórum.

`operacion.json`, que conserva resultados y marcas de reconciliación/heartbeat,
se actualiza bajo un único candado mediante temporal, `os.replace` y `fsync` del
fichero y del directorio. Un corte no puede publicar un JSON parcialmente
escrito como evidencia de preparación.

## Ledger fusionable

El ledger no elige ciegamente la revisión mayor. Sus marcas representan cuota
consumida y se fusionan conservadoramente:

- unión de intentos semanales y fallos horarios;
- `agotado` verdadero si cualquier miembro lo observó;
- siguiente intento más tardío;
- reconciliación pendiente más reciente;
- finalización sólo cuando no es anterior a la reconciliación;
- nueva revisión cuando dos contenidos válidos divergían.

El primario, su copia y las escrituras usan validación estricta, reemplazo
atómico y `fsync`. Si ambos estados son ilegibles, no se renueva.

### Claves de cuota

La cuota de certificados duplicados se indexa por SHA-256 del **conjunto SAN
exacto**, ordenado, sin punto final, en minúsculas e IDNA. Cambiar el ID SQL o
recrear una fila no reinicia la ventana. Un conjunto con sólo apex y otro con
apex más wildcard son emisiones distintas.

Los fallos de autorización se cuentan por identificador DNS base entre todas las
entradas solapadas. Para este límite:

- `example.net` aporta `example.net`;
- `*.example.net` también aporta `example.net`;
- ambos comparten los fallos horarios del mismo identificador.

El máximo automático es cuatro por semana y cuatro fallos por identificador y
hora. La vía manual puede usar el quinto, nunca un sexto. Una emisión correcta
permanece en la ventana semanal; no borra consumo.

## Transacción de renovación

Todas las vías comparten el mismo cerrojo y no se solapan con la captura de un
snapshot. El flujo es:

1. confirmar activo y reconciliar configuración/ledger con quórum;
2. verificar la cuota SAN e identificar solapamientos ambiguos;
3. registrar `en_curso` y replicar la reserva al quórum;
4. volver a confirmar autoridad justo antes del `POST` a NPM;
5. esperar que cambie el fingerprint del PEM guardado;
6. comprobar por TLS el fingerprint DER exacto en todos los consumidores;
7. recargar Nginx y repetir si aún se sirve el anterior;
8. replicar el snapshot NPM nuevo al quórum;
9. marcar el ledger completado y confirmar esa revisión por quórum.

Sólo después de los nueve pasos se comunica una renovación completa. Si no hay
quórum para reservar, la petición no se envía y la reserva se revierte mediante
una revisión posterior.

Los consumidores TLS incluyen filas activas de:

- `proxy_host`;
- `redirection_host`;
- `dead_host`.

Cada nombre se usa como SNI. Todos deben presentar el fingerprint guardado. Sin
consumidor activo no existe evidencia TLS suficiente y el resultado no se
declara completo.

Un timeout, EOF, reset, error HTTP o respuesta inválida después de iniciar el
`POST` produce estado indeterminado. No se reemite: Guardian relee NPM y reconcilia
el resultado. Si la emisión terminó, continúa activación y réplica usando la
misma reserva; si se confirma el fallo, aplica la espera correspondiente.

Una emisión con TLS pendiente, snapshot sin mayoría o ledger sin mayoría se
notifica como pendiente. Corregir activación o conectividad no debe consumir
otro intento de Let's Encrypt.

## Namecheap opcional

La comprobación de IP y credenciales sólo condiciona certificados DNS-01 cuyo
proveedor sea Namecheap. Si la integración está desactivada, esos certificados
no se renuevan automáticamente, pero:

- la réplica NPM sigue funcionando;
- HTTP-01 sigue siendo elegible;
- otros proveedores no dependen de Namecheap.

Guardian no modifica la lista blanca del proveedor.

## Autenticación humana y 2FA

El login exige canal seguro, activo y quórum. NPM valida la contraseña y devuelve
un token; Guardian vincula una cuenta administradora por ID estable. La
contraseña no se guarda.

La cookie contiene sesión firmada, CSRF y token NPM cifrado, dura inicialmente
15 minutos y está limitada a 5–60. En el perfil seguro usa `HttpOnly`,
`SameSite=Strict` y `Secure`. Cada mutación revalida `/api/users/me`; una cuenta
deshabilitada, sin rol admin, con otro ID o token revocado pierde autorización.

TOTP usa seis dígitos y periodos de 30 segundos. Se generan diez códigos de
recuperación, se conservan sólo sus hashes y el consumo es atómico. El acceso de
emergencia sólo se permite si NPM no responde y no autoriza mutaciones por no
llevar token NPM.

## Canal interno y anti-replay

`NPMG_CLUSTER_TOKEN` deriva mediante HKDF claves distintas para HMAC-SHA-256 y
AES-GCM. El token nunca viaja. Firma y cifrado ligan método, ruta, origen,
destino, timestamp, nonce y huella del cuerpo; las respuestas se ligan además al
nonce de la petición.

Sólo se aceptan pares declarados, con reloj dentro de cinco minutos y destino
exacto. Los nonces consumidos se guardan atómicamente con `fsync` y se conservan
24 horas. Un estado anti-replay corrupto sin copia válida falla cerrado.

Las escrituras de esquema 3 incluyen la huella de membresía en el paquete y
como AAD de AES-GCM. El receptor debe devolver la misma huella verificada para
que su ACK cuente. El esquema 2 sólo permite compatibilidad de tránsito con un
nodo antiguo durante el rolling upgrade: puede transportar estado, pero nunca
acredita el quórum topológico de la versión 1.

Si el inventario semántico ya coincide, el activo envía un heartbeat firmado y
ligado a esa misma huella en vez de detener NPM. El heartbeat sólo renueva la
preparación del pasivo cuando confirma el hash de inventario exacto.

Las URLs internas pueden ser HTTP porque el contenido está autenticado y
cifrado en la aplicación. HTTP no oculta metadatos; limita el puerto a la red
del clúster o usa VPN/TLS si también deben protegerse.

## Portal, NPM y Keepalived

- Portal: proxy HTTPS confiable o `NPMG_ALLOW_INSECURE_PORTAL=1` explícito.
- NPM: HTTPS 443 y CA verificable por defecto; HTTP 81 requiere esquema y
  `NPMG_ALLOW_INSECURE_NPM_API=1`.
- Keepalived: URL HTTPS y CA verificable por defecto; HTTP requiere
  `NPMG_ALLOW_INSECURE_KEEPALIVED_API=1`.

Las tres excepciones son independientes. Una cabecera reenviada desde un origen
no incluido en `NPMG_TRUSTED_PROXY_IPS` no convierte el canal en seguro.

## Garantías y límites

Guardian proporciona captura SQLite coherente, manifiesto, límites de
descompresión, journal durable, recuperación de crash, rollback local,
reconciliación de configuración y ledger y verificación TLS exacta.

La señal pública `ready` tampoco se deriva del proceso Guardian: exige base NPM,
contenedor Docker existente y en ejecución, capacidad receptora, API NPM sana y
sincronía reciente acreditada mediante réplica o heartbeat topológico.

No proporciona:

- escritura síncrona distribuida ni pérdida cero entre snapshots;
- fusión automática de bases NPM divergentes;
- disponibilidad de operaciones sensibles sin mayoría;
- TLS nativo del servidor web;
- ocultación de metadatos del canal interno;
- seguridad del host si el contenedor Guardian, el socket o los secretos se exponen;
- prueba de relevo únicamente a partir de `/api/health`.
