# Runbook de operación y recuperación

## Chequeo diario

Desde la URL HTTPS real:

1. confirma un único activo;
2. revisa salud Guardian, base NPM, contenedor Docker, API y receptor de cada
   miembro; un pasivo sólo está `ready` si todos son correctos y su sincronía es
   reciente;
3. comprueba compatibilidad de secretos y huella de membresía;
4. lee `acknowledged`, `quorum`, `complete` y nodos degradados;
5. confirma comparación completa y última réplica;
6. revisa ledger, resultados indeterminados y próxima ejecución;
7. si Namecheap está activo, comprueba IP y credenciales;
8. revisa avisos de TLS, snapshot o ledger pendientes.

Lectura pública:

```bash
curl --fail --silent http://guardian-a.internal:6061/api/health
curl --fail --silent https://guardian.example.net/api/public/status
```

No uses `/api/health` como prueba de relevo.

## Interpretar el estado

| Estado | Interpretación |
| --- | --- |
| Activo | autoridad de la VIP; las mutaciones aún requieren canal, sesión y quórum |
| Pasivo | vista reducida y receptor, sin portal privado |
| Desconocido | autoridad perdida; todas las escrituras bloqueadas |
| `ok=true`, `complete=true` | quórum y todos los miembros confirmaron |
| `ok=true`, `complete=false` | mayoría alcanzada, servicio degradado |
| `ok=false` | sin mayoría; no declarar durable la operación |
| Comparación incompleta | no se sabe si el ausente coincide |
| Secretos incompatibles | ese nodo no puede aportar estado ni quórum |
| Topología incompatible | su ACK no aporta quórum; revisa `NPMG_NODES`, nodo y pares |
| `ready=false` | falta DB, Docker, API, receptor o sincronía topológica reciente |

En tres miembros, `2/3` permite continuar degradado. No confundas tolerar una
ausencia con tener tres copias actualizadas.

## Acceso inicial seguro

Si el primer login falla:

1. abre exactamente `NPMG_PUBLIC_URL` por HTTPS;
2. verifica el certificado del proxy;
3. confirma que el upstream llega al Guardian activo;
4. comprueba que el proxy envía un único `X-Forwarded-Proto: https`;
5. verifica que su origen, visto dentro del contenedor, pertenece a
   `NPMG_TRUSTED_PROXY_IPS`;
6. comprueba quórum y compatibilidad de secretos;
7. comprueba que `NPMG_NODES` coincide exactamente con el nodo local más sus
   pares y que todos publican la misma huella;
8. prueba la misma cuenta directamente en el NPM activo;
9. confirma cuenta habilitada y rol administrador.

`426 HTTPS_REQUIRED` es un fallo de transporte, no de contraseña.
`503 CLUSTER_STATE_UNAVAILABLE` es falta de mayoría, no de NPM.

Si se ha elegido conscientemente un perfil LAN, confirma las tres excepciones
por separado. No habilites HTTP sólo para hacer desaparecer un error de CA.

## Quórum perdido

Con sólo el activo disponible:

- no repitas login ni mutaciones esperando que entren;
- no intentes renovar manualmente;
- no cambies secretos ni borres revisiones;
- conserva el NPM activo sirviendo tráfico;
- recupera al menos un par con la misma topología y secretos;
- espera la reconciliación o consulta de nuevo el estado;
- verifica `acknowledged >= quorum` antes de continuar.

La reconciliación vota por contenido lógico y excluye `revision` y
`updated_at`. Una revisión alta aislada no gana. Si dos nodos sostienen el mismo
contenido y existe un huérfano con revisión mayor, Guardian publica el contenido
confirmado como `max + 1`; no continúes hasta que ese rebase alcance quórum.

Si no hay un único hash lógico respaldado por mayoría, preserva archivos,
revisiones y hashes y mantén las mutaciones bloqueadas. No edites
`guardian.json` a mano para elegir un ganador.

## Sincronización y recuperación automática

1. confirma activo y comparación completa;
2. revisa la fuente lógica indicada;
3. usa la sincronización ordinaria: si una única fuente remota conserva todos
   los cambios funcionales, el activo la recuperará y redistribuirá;
4. espera el resultado por receptor;
5. comprueba `ok` y `complete` por separado;
6. vuelve a comparar inventarios;
7. prueba API NPM y un proxy en cada receptor actualizado.

Un nodo caído no impide enviar a los demás. En tres miembros, llegar a uno de
los dos pasivos forma quórum, pero el ausente debe sincronizarse al regresar.
Una recuperación desde un pasivo sí exige comparación completa: no se elige
una fuente mientras falte un miembro por consultar.

### Imponer el activo

Sólo procede si:

- se ha determinado externamente la copia correcta;
- los cambios remotos son descartables o están preservados;
- existe respaldo válido;
- se acepta reemplazar todo el conjunto administrado.

Registra motivo, operador y resultado. `forzar=true` no fusiona datos.

## Renovar un certificado

Antes:

1. confirma activo y quórum;
2. revisa conjunto SAN y cuota semanal;
3. revisa fallos por identificador DNS; wildcard y apex comparten nombre base;
4. confirma acceso técnico NPM;
5. para DNS-01 Namecheap, comprueba integración, IP y huella de credenciales;
6. identifica todos los consumidores activos: proxy, redirección y dead hosts.

Después, no declares éxito hasta ver:

- fingerprint del PEM guardado distinto al anterior;
- fingerprint DER servido correcto en todos los SNI;
- snapshot NPM con `ok=true`;
- ledger final con `ok=true`.

`complete=false` en cualquiera de las réplicas indica degradación pendiente.

### Timeout o respuesta indeterminada

Un timeout, reset, EOF o error después de enviar puede ocultar una emisión
correcta. Guardian conserva la reserva y bloquea emisiones solapadas.

No pulses de nuevo. Comprueba:

1. fingerprint y caducidad guardados en NPM;
2. certificado servido por TLS;
3. estado de reconciliación del ledger;
4. logs NPM y Certbot;
5. conectividad de quórum.

La vigilancia resolverá el mismo intento. Sólo un fallo confirmado habilita la
espera y un reintento posterior.

### PEM nuevo, TLS antiguo

Guardian intenta recargar Nginx y vuelve a consultar cada SNI. Si sigue
pendiente:

- revisa el consumidor concreto indicado;
- valida `nginx -t` y logs;
- comprueba SNI, DNS y `NPMG_NPM_HTTPS_PORT`;
- revisa proxy hosts, redirecciones y dead hosts asociados;
- confirma que el endpoint realmente termina TLS en ese NPM.

Corrige la activación y vuelve a comprobar. No emitas otro certificado.

### Sin consumidor TLS

Un certificado guardado sin host activo asociado no puede demostrarse servido.
Asócialo a un consumidor válido o acepta que la renovación siga no verificable;
no conviertas la ausencia de SNI en éxito.

### Snapshot o ledger sin quórum

La emisión puede haber ocurrido y el TLS puede ser correcto, pero la transacción
no está completa. Recupera un par y deja converger:

- si falta snapshot, sincroniza el estado NPM sin reemitir;
- si falta ledger, reconcilia el estado de Guardian sin reemitir;
- conserva el aviso hasta observar mayoría.

## Incidencias de transporte

### API NPM no disponible

Comprueba esquema, puerto y CA como una unidad:

- seguro inicial: `https`, puerto `443`, CA pública o
  `NPMG_NPM_CA_FILE` válido;
- LAN explícita: `http`, puerto `81` y
  `NPMG_ALLOW_INSECURE_NPM_API=1`.

El nombre de `NPMG_NODE_ADDRESS` debe coincidir con la identidad del certificado
TLS. No desactives validación por un SAN incorrecto.

### Keepalived no disponible

Consulta la URL desde la red del contenedor. Verifica servicio, estado `en_uso`,
portador, esquema, `NPMG_KEEPALIVED_CA_FILE` y que la clave configurada mediante
`NPMG_KEEPALIVED_API_TOKEN[_FILE]` siga activa con `status:read`. HTTP exige su opt-in
específico. Mientras la autoridad sea desconocida, no fuerces operaciones.

### Pares internos no responden

Revisa:

- URL y firewall;
- nombres recíprocos;
- igualdad exacta entre `NPMG_NODES` y `NPMG_NODE_NAME` + `NPMG_PEERS`;
- misma huella de membresía en los tres nodos;
- reloj;
- identificadores de secretos;
- firma, target y versión de protocolo;
- estado anti-replay;
- rol del receptor.

Un `401` interno indica identidad, reloj, firma o sobre inválido. Un `409` puede
indicar replay, receptor activo u operación ocupada. No borres nonces para
reutilizar una petición capturada.

El esquema 3 liga la huella topológica al AAD y exige que el receptor la
confirme. Un ACK de esquema 2 sólo mantiene compatibilidad durante la
actualización escalonada y no cuenta para quórum; no rebajes manualmente el
contrato para hacer desaparecer una degradación.

## Configuración o 2FA no convergentes

La reconciliación se ejecuta de forma periódica, independiente del cron NPM.

1. comprueba que el activo alcanza quórum topológico;
2. compara el hash lógico de configuración, además de revisión y ledger;
3. confirma membresía e identificadores de secretos iguales;
4. si aparece un rebase, verifica que su revisión supera la máxima observada y
   que su réplica alcanzó mayoría;
5. espera un ciclo y vuelve a consultar;
6. si ningún contenido obtiene mayoría, conserva evidencias y detén cambios.

No copies `guardian.json`, ledger ni códigos a mano. Un código de recuperación
consumido no debe reaparecer desde un nodo rezagado.

## Journal o réplica interrumpida

Guardian procesa `/datos/replica-transaction.json` al arrancar. Antes de tocar:

1. impide que el nodo reciba la VIP;
2. conserva journal, `.old`, logs y hashes;
3. reinicia únicamente Guardian para permitir la recuperación automática;
4. observa la acción `prepared-cleaned`, `promoted-swap-completed`,
   `promoted-swap-rolled-back`, `rolled-back` o `commit-cleaned`;
5. verifica NPM, SQLite, API, proxies y certificados.

Si el journal es corrupto o la recuperación falla, el cierre seguro puede dejar
NPM detenido. No borres el journal ni arranques NPM sobre rutas parciales.
Extrae una copia forense y restaura bajo un procedimiento controlado.

La recuperación hacia delante se decide y sincroniza antes del primer `rename`.
Si el estado nuevo no recupera salud, Guardian hace durable la decisión de
rollback antes de invertir nombres, restaura el anterior y vuelve a comprobar
salud. Un fallo de `fsync` conserva journal y rutas para el siguiente análisis.

## NPM no recupera salud

1. mantén el nodo fuera del reparto;
2. conserva los tres respaldos `antes-de-replicar-*` y el journal;
3. revisa `database.sqlite` con `quick_check` sobre una copia;
4. identifica si la transacción estaba confirmada o en rollback;
5. restaura sólo las rutas del mismo snapshot, preservando enlaces;
6. arranca NPM y valida API, Nginx y TLS;
7. compara con el activo antes de reincorporar.

No mezcles base de un respaldo con certificados de otro.

## Autenticación y 2FA

### Credenciales rechazadas

- prueba la cuenta en el NPM activo;
- confirma el ID vinculado, rol admin y cuenta habilitada;
- verifica que el token no se haya revocado;
- inicia sesión de nuevo si cambió la contraseña;
- espera la ventana del limitador si hubo demasiados fallos.

### Emergencia

Sólo aparece cuando NPM no responde y 2FA ya estaba activo. Consume un código y
no permite mutaciones. Si NPM devuelve un rechazo normal, no es una caída y la
vía permanece cerrada.

### Secreto de sesión cambiado

Restaura el valor anterior desde el gestor seguro. Un valor nuevo no puede
descifrar credenciales ni TOTP existentes y produce incompatibilidad de clave.
No pruebes secretos al azar.

## Namecheap

### IP rechazada

Actualiza la lista blanca desde el proveedor y vuelve a comprobar. Guardian no
puede modificarla. No emitas mientras el estado sea rechazado o indeterminado.

### Credencial distinta en NPM

Guardian compara usuario y huella de la clave configurada en el certificado.
Corrige la fuente elegida y vuelve a validar antes de DNS-01. No afecta a
HTTP-01 ni a la réplica básica.

## Mantenimiento y actualización

1. confirma el portador y mueve la VIP mediante el sistema autorizado si hace
   falta;
2. actualiza pasivos uno a uno;
3. verifica `1.0.5`, vista reducida, secretos, huella topológica, NPM y receptor;
4. actualiza el activo al final;
5. verifica login HTTPS, quórum, sincronización y TLS;
6. verifica que `icono.png` es PNG 128 × 128 y que su SHA-256 coincide en
   `/var/local/emhttp/plugins/dynamix.docker.manager/images/` y
   `/var/lib/docker/unraid/images/`;
7. confirma que el despliegue retiró el rollback y cualquier contenedor o red
   heredados de la antigua topología de dos contenedores.

Para el despliegue genérico puede declararse `NPMG_ACTIVE_NODE`; el guion ordena
los pasivos antes del activo. Una referencia `:1.0.5` debe llevar metadatos OCI
`1.0.5` y responder lo mismo en `/api/version`.

La versión no se publica en el repositorio compartido ni recibe el tag `v1.0.5` hasta
completar estas comprobaciones.

La evidencia automática actual son 136 pruebas superadas dentro de las imágenes
ARM64 y AMD64, más el laboratorio Docker real con NPM 2.15.1 en ambas. Deben
acompañarse de las comprobaciones operativas anteriores; no
constituyen por sí solas despliegue, tag ni publicación.

## Rollback de Guardian

Volver a la imagen anterior no implica restaurar NPM. Mantén `/datos`, `/npm` y
`/npm-letsencrypt`; restaura datos sólo ante corrupción o migración demostrada.
Usa el contenedor anterior conservado, valida su digest antes de devolverle el
nombre operativo y no lo elimines hasta cerrar la ventana acordada. Después
repite salud, rol, membresía, quórum, login, inventario y servicio TLS.

## Evidencias

Conserva sin secretos:

- fecha, zona, commit, versión y digest;
- rol y autoridad observados;
- `acknowledged`, `quorum`, `complete` y nodos fallidos;
- revisiones de configuración y ledger;
- clave SAN truncada o ID de certificado, nunca credenciales;
- fases de PEM, TLS, snapshot y ledger;
- journal, respaldo y hashes relevantes;
- logs de Guardian, NPM, Nginx y Certbot;
- prueba final desde fuera del contenedor.
