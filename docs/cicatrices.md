# Cicatrices y decisiones defensivas

Estas reglas nacen de fallos posibles o ya observados. Aunque cambie la
implementación, no deben desaparecer sin una garantía equivalente y pruebas.

## Autoridad y disponibilidad

### Desconocido no significa activo

Una API flotante caída, ambigua o sin servicio produce rol desconocido. Nunca se
renueva, replica ni recibe estado bajo la suposición de que «nadie más manda».

### La VIP decide rol; el quórum decide durabilidad

Ser portador autoriza a proponer una operación, no a confirmarla en solitario.
En tres miembros hacen falta `2/3`. Un nodo ausente es degradación visible;
dos ausentes bloquean cambios sensibles.

### Un contenedor arrancado no demuestra relevo

Hay que separar proceso Guardian, autoridad, quórum, Docker, SQLite, API NPM,
réplica reciente y TLS. Un único indicador verde no resume todos esos estados.

Un pasivo sólo declara `ready` cuando DB, contenedor Docker, capacidad receptora
y API NPM están sanos y existe una réplica o heartbeat autenticado, ligado a la
topología y todavía reciente.

### Los pasivos no son una aplicación deshabilitada

Sirven una interfaz reducida propia, sin botones que deban fallar. Pedir
`/index.html` directamente tampoco evita la decisión de rol.

## Bootstrap y estado de Guardian

### Tres configuraciones iniciales no deben competir

El documento virgen es determinista. Sólo el activo puede promoverlo antes de
vincular la cuenta, y el primer login requiere mayoría. Así no nacen identidades
distintas durante un arranque aislado.

### Una revisión alta aislada no es un commit

El activo puede caer después de persistir localmente y antes del quórum. Por eso
la reconciliación vota por hash del contenido lógico y excluye `revision` y
`updated_at`: sólo un contenido presente en mayoría puede ganar. Si existe un
huérfano con revisión superior, el ganador se publica como `max + 1` y ese
rebase debe alcanzar quórum antes de continuar. Sin mayoría inequívoca se falla
cerrado; timestamp, revisión máxima o «último en contestar» no eligen ganador.

### La membresía forma parte del quórum

Dos listas distintas pueden calcular mayorías que no intersectan. Por eso
`NPMG_NODES` debe coincidir exactamente con el nodo local más sus pares, y su
huella cerca el esquema 3 y el AAD cifrado. El esquema 2 sirve únicamente para
el tránsito durante rolling upgrade y nunca acredita quórum v1.

### La cuota no se resuelve con last-write-wins

Un nodo rezagado no puede borrar intentos o códigos consumidos. El ledger se
fusiona mediante unión conservadora y crea una revisión nueva al reconciliar
divergencias válidas.

### La convergencia no puede depender del cron NPM

Cuenta, 2FA y ledger necesitan un bucle propio. Desactivar snapshots no debe
impedir que el estado de seguridad cure a un miembro que vuelve.

### Un primario corrupto no autoriza reiniciar desde cero

Configuración, ledger y anti-replay usan copia válida. Si primario y copia son
ilegibles, se falla cerrado; regenerar silenciosamente perdería cuenta, cuota o
protección de replay.

### El estado operativo también necesita atomicidad

`operacion.json` alimenta la antigüedad de réplica y `ready`. Se serializa bajo
candado y se publica mediante temporal, reemplazo atómico y `fsync` de fichero y
directorio; un JSON truncado no puede acreditar preparación.

## Snapshot y réplica

### Copiar una SQLite viva como archivo no es un snapshot

Se usa la API de backup y `quick_check`. Además se compara una segunda copia y
la huella de artefactos antes/después. Si NPM cambia, se reintenta o se aborta.

### Cifrado no demuestra coherencia de origen

AES-GCM protege los bytes en tránsito, no el momento de captura. Por eso existen
estabilidad previa/posterior, manifiesto y comprobaciones SQLite separadas.

### Limitar el comprimido no limita la expansión

Se aplican límites independientes al `tar.gz`, tamaño expandido, número de
miembros y manifiesto. Una bomba comprimida válida criptográficamente sigue
siendo entrada hostil.

### Los enlaces Certbot son necesarios y peligrosos

`live/` enlaza a `archive/`. Deben conservarse, pero sólo si su resolución queda
dentro del paquete. Convertirlos o permitir escapes rompe Certbot o el host.

### El receptor valida antes de parar

Firma, sobre, replay, rol, límites, rutas, manifiesto y SQLite se comprueban
antes de tocar NPM. Reducir la ventana parada no justifica validar después.

### Un crash necesita memoria durable

El journal se escribe y sincroniza antes de detener NPM y en cada fase de
publicación. Sin `fsync`, un JSON visible en caché no garantiza recuperación tras
un corte real.

La recuperación hacia delante debe quedar durable antes del primer `rename`.
Si el estado nuevo no recupera salud, la decisión de rollback se sincroniza
antes del primer `rename` inverso y el estado anterior también debe demostrar
salud. Un fallo de `fsync` conserva journal y `.old`.

### Un rollback incierto no debe arrancar

Si no puede demostrarse la restauración, se conservan journal y `.old` y NPM
queda detenido. Servir un estado parcial es peor que una indisponibilidad
diagnosticable.

### Base y certificados son una unidad

Restaurar SQLite de una fecha y Certbot de otra crea referencias rotas. Snapshot
y rollback siempre operan sobre el mismo conjunto.

## Renovación

### Un HTTP 200 de NPM no es una renovación

Sólo indica aceptación. Hay que observar cambio de PEM, TLS real y durabilidad
en quórum antes de comunicar éxito completo.

### Guardado y servido son estados diferentes

El PEM puede cambiar mientras Nginx mantiene el anterior. Se compara fingerprint
DER exacto, se recarga si hace falta y se verifican todos los consumidores.

### Proxy, redirección y dead host consumen TLS

Limitar la prueba a `proxy_host` deja certificados aparentemente correctos que
fallan en `redirection_host` o `dead_host`. Cada fila activa asociada aporta SNI
y todas deben coincidir.

### Sin consumidor no hay evidencia de servicio

La ausencia de un endpoint TLS no convierte el PEM guardado en certificado
servido. El resultado queda no verificable hasta disponer de consumidor.

### Un timeout puede esconder un éxito

Una vez comenzado el `POST`, timeout, EOF, reset, error HTTP o JSON inválido son
indeterminados. Se relee NPM y se bloquea otra emisión solapada.

### La cuota pertenece al SAN, no a la fila

Recrear un certificado con otro ID no reinicia el límite. La clave usa el
conjunto SAN exacto canónico y conserva éxitos durante la ventana semanal.

### Wildcard y apex comparten fallos de autorización

Para la cuota de fallos, `*.example.net` se reduce a `example.net`. Los fallos
se agregan entre certificados que comparten identificador, aunque sus conjuntos
SAN de emisión sean distintos.

### El intento se reserva antes de emitir

Sin ledger en mayoría no se envía la petición. Si una reserva parcial no logra
quórum, se revierte mediante una revisión posterior para que los pares
converjan sin dejar una emisión fantasma.

### Emitido no significa durable

Después de TLS correcto, snapshot y ledger deben alcanzar mayoría. Si no, se
recupera conectividad y se replica; nunca se compra otro certificado para
resolver un problema de clúster.

### Namecheap no es la función base

Su estado sólo condiciona DNS-01 Namecheap. Mantenerlo desactivado no debe
bloquear HA, snapshots, HTTP-01 ni otros proveedores.

## Identidad y secretos

### Guardian no conserva otra contraseña humana

El NPM activo autentica. Guardian vincula el ID, guarda TOTP y emite sesión. Una
mutación vuelve a comprobar token, rol, estado e ID en `/api/users/me`.

### Emergencia no es puerta trasera

Sólo se habilita cuando NPM no responde, 2FA estaba activo y se consume un
código. La sesión no lleva token NPM y no muta.

### Compartir secreto no basta; hay que detectar diferencias

Los identificadores HMAC de claves permiten marcar un miembro incompatible sin
revelar el secreto. Un nodo con otra clave no aporta quórum ni descifra estado.

### Rotar el secreto de sesión requiere migración

Cambiarlo directamente invalida cookies y vuelve ilegibles credenciales y TOTP.
No se trata como una contraseña local ordinaria.

## Transporte

### Una cabecera HTTPS sólo vale desde el proxy

Aceptar `X-Forwarded-Proto` de cualquier cliente permitiría marcar HTTP como
seguro. Guardian valida el origen contra CIDR exactos y exige un solo valor.

### Los tres canales inseguros son decisiones separadas

Portal, API NPM y API Keepalived tienen opt-ins distintos. La necesidad de HTTP
81 en una LAN no debe rebajar el login ni la autoridad flotante.

### Una CA privada es mejor que desactivar TLS

NPM y Keepalived aceptan rutas de CA dentro del contenedor. Un error de SAN o de
confianza se corrige en certificados y nombres, no suprimiendo verificación.

### El cifrado interno no oculta metadatos

HMAC y AES-GCM protegen contenido, integridad y replay. IP, ruta, tamaño y tiempo
siguen visibles; firewall, VPN o TLS adicional cubren ese riesgo.

## Superficie operativa

### El socket Docker sigue siendo privilegiado

El único contenedor de NPM Guardian monta el socket y su cliente integrado sólo
implementa inspección, `start/stop` del NPM exacto y dos órdenes Nginx fijas.
La lista blanca reduce errores y abuso accidental, pero comprometer el proceso
conserva el riesgo inherente de alcanzar el daemon Docker del host.

### Las confirmaciones pertenecen a la aplicación

`alert`, `confirm` y `prompt` rompen estilo, accesibilidad y control de foco. Se
mantienen modales y toasts propios en ambas vistas.

### Identidad visual también es contrato

Título `NPM Guardian`, icono antes del título y PNG 128 × 128 deben existir en
activo y pasivo. En Unraid, el mismo contenido debe quedar comprobado por hash
en las dos cachés de DockerMan; actualizar sólo una deja iconos obsoletos.

### El rollback no se elimina nodo a nodo

Que un nodo nuevo supere su healthcheck no demuestra que el conjunto sea
compatible. El contenedor anterior se conserva renombrado durante la validación
completa y sólo se retira al cerrar conscientemente la ventana de rollback.

### Los booleanos se analizan, no se adivinan

La presencia de `forzar=false` no activa una imposición. Sólo valores definidos
como verdaderos habilitan acciones de riesgo.

### Un arnés no puede fijar para siempre quién es el activo

Durante la validación física la autoridad cambió entre el precheck y una prueba
de aislamiento. El producto mantuvo un único activo, pero el arnés había fijado
un nodo y abortó. Cada frontera redescubre ahora la autoridad inmediatamente
antes de detener, replicar o restaurar; el fallo del arnés se registra y su
repetición corregida es la única que cuenta como evidencia.

### Un filtro de puerto no descubre de forma fiable un contenedor parado

En el Docker clásico del host, `docker ps -a --filter publish=...` no devolvió
el runtime detenido durante una recuperación. Rollback y rejoin usan el nombre
capturado y validado antes de parar, nunca una nueva búsqueda por puerto.

### Los metadatos de tar dependen del filesystem de destino

El backup conserva propietarios numéricos, modos, xattrs y ACL. El filesystem
de `/datos` validado no permite reaplicar ACL POSIX, aunque sí conserva el resto
del estado necesario. La prueba de restauración debe tratar el aviso de ACL de
forma explícita y verificar después propietarios, modos e inventario; no debe
ocultarlo ni confundirlo con corrupción.

## Límites conscientes

- No hay consenso distribuido: la API flotante sigue siendo autoridad externa.
- No hay fusión automática si las bases NPM tienen ganadores lógicos
  repartidos. Una fuente lógica única sí puede recuperarse automáticamente.
- No hay pérdida cero entre snapshots asíncronos.
- El servidor integrado no termina TLS.
- El socket Docker exige confianza en el host y en el contenedor Guardian que lo monta.
- No hay token externo de automatización para mutaciones en 1.0.5.

Cuando una limitación desaparezca, deben actualizarse código, pruebas, modelo de
amenazas y este documento en el mismo cambio.
