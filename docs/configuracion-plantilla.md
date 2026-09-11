# Configuración y plantilla

## Qué pertenece a la plantilla

La plantilla Unraid 1.0.4 contiene exactamente cinco campos. Todos son parte del
contrato del contenedor, no de la lógica de NPM Guardian:

| Campo | Destino | Motivo |
|---|---|---|
| Puerto del panel | `6061/tcp` | abrir la WebUI |
| Datos de NPM | `/npm` | leer y replicar `database.sqlite` y datos asociados |
| Certificados de NPM | `/npm-letsencrypt` | replicar certificados |
| Datos de Guardian | `/datos` | conservar configuración, secretos y estado |
| Socket Docker | `/var/run/docker.sock` | detener, arrancar y validar únicamente el NPM indicado |

No hay campos de tipo `Variable`, directorio `/run/secrets`, credenciales,
direcciones de servidores ni valores propios de una instalación concreta.

## Qué se configura dentro de la aplicación

En el primer inicio el panel solicita:

- nombre y dirección del nodo;
- miembros y URLs Guardian del clúster;
- modo HA o independiente;
- URL, servicio y token API de Keepalived;
- URL pública, proxy de confianza o aceptación explícita de HTTP en LAN;
- nombre del contenedor NPM, esquema y puertos de su API;
- código de incorporación, salvo en el primer nodo.

`/datos/node.json` conserva la parte local. Los secretos se escriben como
ficheros regulares `0600` bajo `/datos/secrets`; el token de Keepalived no forma
parte de `node.json`.

## Código de incorporación

Al configurar el primer nodo sin código, NPM Guardian crea dos valores aleatorios
distintos: secreto de sesión y token de clúster. La respuesta muestra una
representación transportable de ambos una sola vez.

Configura los nodos restantes pegando exactamente ese código. Cada nodo obtiene
sus propias direcciones del formulario, pero comparte la identidad criptográfica
del grupo. No crees un clúster nuevo en cada servidor.

## Compose

`.env.example` sólo contiene la referencia de imagen, el puerto host y rutas
host de los cuatro montajes. `docker-compose.yml` declara un servicio y añade
`host.docker.internal:host-gateway` para alcanzar Keepalived en el servidor.

```sh
cp .env.example .env
docker compose config
docker compose up -d --build
```

## Compatibilidad con instalaciones anteriores

Las variables `NPMG_*` y sus alias históricos `NPMHA_*` siguen aceptándose para
no romper contenedores instalados. Si existe una configuración legacy completa,
Guardian arranca con ella y permite migrarla guardando la configuración local
desde el portal. Cuando existe `node.json`, sus valores son autoritativos.

Este mecanismo de compatibilidad no justifica reintroducir variables en la
plantilla pública.

## Imagen

Una plantilla no construye una imagen: Unraid descarga la referencia de
`<Repository>`. La publicación compartida deberá proporcionar
`ghcr.io/ezr43l/npm-guardian-s:1.0.4` para las arquitecturas Linux declaradas.
