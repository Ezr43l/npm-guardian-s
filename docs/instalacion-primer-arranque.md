# Instalación y primer arranque

## Requisitos

- un servidor Docker Linux o Unraid;
- una instancia Nginx Proxy Manager por nodo;
- Keepalived configurado si se usará alta disponibilidad;
- conectividad entre las URLs Guardian de los miembros;
- un directorio persistente distinto para Guardian en cada servidor.

## 1. Crear el contenedor en Unraid

Instala la plantilla `unraid/my-NPM-Guardian.xml` y completa sólo:

1. el puerto de la WebUI, normalmente `6061`;
2. la ruta `data` del NPM de ese servidor;
3. la ruta `letsencrypt` del mismo NPM;
4. una ruta nueva para datos de Guardian;
5. `/var/run/docker.sock`.

No añadas secretos, nodos o URLs como variables. Inicia el contenedor y abre la
WebUI. Mientras falte configuración, `/api/health` responde
`{"status":"setup-required"}`.

## 2. Preparar la lista de miembros

Para cada servidor anota:

- un nombre estable, igual al nombre que Keepalived informa como activo;
- la dirección por la que se alcanza el NPM de ese servidor;
- la URL del panel Guardian desde los otros servidores.

El asistente usa una línea por miembro:

```text
node-a | npm-a.internal | http://guardian-a.internal:6061
node-b | npm-b.internal | http://guardian-b.internal:6061
node-c | npm-c.internal | http://guardian-c.internal:6061
```

En cada servidor, la URL de su propia línea puede quedar vacía. La lista de
nombres debe ser idéntica en todos los miembros.

## 3. Configurar el primer nodo

1. Escribe su nombre y dirección.
2. Pega la lista completa de miembros.
3. Deja vacío **Código de incorporación**.
4. Indica la URL y el nombre de servicio de Keepalived.
5. Pega el token API de Keepalived. Se guardará bajo `/datos/secrets`.
6. Elige transporte HTTPS o acepta expresamente HTTP sólo si se mantiene dentro
   de la LAN de confianza.
7. Indica el proxy HTTPS de confianza. Si todavía accederás directamente por
   LAN, marca temporalmente el permiso de portal HTTP.
8. Escribe el nombre exacto del contenedor NPM y su esquema/puertos.
9. Guarda.

Guardian muestra un código de incorporación. Cópialo antes de abandonar la
pantalla; contiene la identidad compartida del clúster y debe custodiarse como
un secreto.

## 4. Configurar los demás nodos

Repite la creación del mismo contenedor en cada servidor, usando sus rutas NPM
locales. En el asistente:

1. selecciona el nombre y dirección correspondientes al servidor actual;
2. conserva la misma lista de miembros;
3. pega el código generado por el primer nodo;
4. completa la conexión local con NPM y Keepalived;
5. guarda y comprueba que el proceso pasa a estado `ok`.

No dejes vacío el código en los nodos adicionales: hacerlo crearía otro grupo
criptográfico y las réplicas serían rechazadas.

## 5. Primer acceso

Con una mayoría de nodos disponible, abre la URL del activo e inicia sesión con
una cuenta administradora de NPM. El primer acceso vincula su ID estable y
replica esa identidad antes de abrir la sesión. Después configura, desde el
panel, sincronización, credenciales técnicas de NPM, Namecheap si se usa y 2FA.

## 6. Comprobaciones

- la plantilla muestra cinco campos y un solo contenedor;
- `/api/health` responde `ok` tras finalizar el asistente;
- `/datos/node.json` existe y no contiene el token de Keepalived;
- `/datos/secrets/session-secret` y `cluster-token` coinciden entre nodos;
- Estado identifica un único activo y el resto como pasivos;
- una sincronización de prueba llega a los pasivos sin cambiar el activo;
- no queda ningún contenedor `docker-control` ni un segundo Guardian.

## Actualizaciones

Conserva `/datos`, los dos directorios NPM y la referencia al socket. Sustituye la
imagen de los pasivos uno a uno, valida su salud y actualiza el activo al final.
No borres `node.json` ni `secrets`: hacerlo convierte el contenedor en una
instalación nueva.

Las instalaciones legacy que ya usan `NPMG_*` pueden actualizarse sin migración
forzada. Al guardar la configuración local desde el portal, Guardian copia los
secretos administrados a `/datos`, crea `node.json` y pasa a usarlo como fuente
autoritativa.
