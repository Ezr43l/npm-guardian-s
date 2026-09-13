# API e integraciones

## Contrato 1.0.6

Las rutas viven bajo `/api/` sin prefijo de versión. Su compatibilidad forma
parte del contrato semántico de 1.0.6.

Las respuestas JSON usan UTF-8, `Cache-Control: no-store` y errores estables:

```json
{
  "error": "Mensaje legible",
  "code": "ERROR_ESTABLE",
  "detail": {
    "code": "ERROR_ESTABLE",
    "message": "Mensaje legible"
  }
}
```

## Transporte

El servidor integrado atiende HTTP. En el perfil seguro, todo `POST` o `DELETE`
humano exige:

- origen dentro de `NPMG_TRUSTED_PROXY_IPS`;
- exactamente un `X-Forwarded-Proto: https`;
- `NPMG_ALLOW_INSECURE_PORTAL=0`.

Un incumplimiento devuelve `426 HTTPS_REQUIRED`. Guardian no confía en esa
cabecera desde un cliente cualquiera. Las lecturas públicas permiten comprobar
salud directa sin enviar credenciales.

## Superficie pública

| Método y ruta | Función |
| --- | --- |
| `GET /api/health` | proceso, producto, nodo y versión |
| `GET /api/version` | identidad de producto y versión |
| `GET /api/public/status` | rol, activo, VIP, enlace y salud local |
| `DELETE /api/session` | borra la cookie; requiere canal sensible |

```bash
curl --fail --silent http://guardian-a.internal:6061/api/health
curl --fail --silent https://guardian.example.net/api/public/status
```

`/api/health` no demuestra quórum, réplica reciente ni preparación para tomar la
VIP. `last_sync` es una marca local y no prueba recepción en un pasivo.

## Sesión humana

### Login normal

```http
POST /api/session
Content-Type: application/json

{"username":"operator@example.net","password":"<contraseña>","otp":"123456"}
```

Antes de autenticar, el activo reconcilia configuración y ledger y exige
quórum. Después:

1. solicita token al NPM activo;
2. consulta `/api/users/me`;
3. exige cuenta habilitada y administradora;
4. vincula o comprueba el ID NPM estable;
5. valida TOTP cuando está activo;
6. emite cookie y `csrf_token`.

La cookie es `HttpOnly`, `SameSite=Strict` y `Secure` en el perfil seguro. Su
duración inicial es 15 minutos y admite 5–60. El token NPM se cifra dentro de la
sesión y se usa para revalidar cada mutación; la contraseña no se persiste.

### Emergencia

Sólo cuando NPM no responde:

```json
{
  "emergency": true,
  "username": "operator@example.net",
  "recovery_code": "XXXX-XXXX-XXXX-XXXX"
}
```

Exige cuenta vinculada, 2FA habilitado, código válido y quórum. El consumo es
atómico. Si NPM responde, incluso para rechazar credenciales, esta vía queda
bloqueada. La sesión de emergencia no contiene token NPM y no puede mutar.

### Consulta

`GET /api/session` requiere cookie válida y nodo activo. Devuelve identidad,
estado 2FA, códigos restantes, vencimiento y CSRF, nunca secretos.

## Lecturas privadas

Todas requieren activo y sesión.

| Ruta | Contenido |
| --- | --- |
| `GET /api/mando` | autoridad y motivo |
| `GET /api/certificados` | certificados, SAN y días restantes |
| `GET /api/dominios` | proxy hosts, destinos y certificado |
| `GET /api/vigilancia` | última revisión, renovaciones y ledger resumido |
| `GET /api/namecheap` | IP y estado de lista blanca |
| `GET /api/credenciales` | comparación de huellas DNS |
| `GET /api/sincronia` | inventarios, ganadores y nodos sin respuesta |
| `GET /api/estado` | cuadro agregado del portal |
| `GET /api/config` | ajustes no secretos, siguiente cron y topología |
| `GET /api/profile` | identidad vinculada y 2FA |

## Mutaciones privadas

Exigen canal sensible, activo, cookie, `X-CSRF-Token` y revalidación de la cuenta
en NPM. Configuración, perfil, 2FA y renovación exigen además reconciliación con
quórum.

| Método y ruta | Efecto |
| --- | --- |
| `POST /api/config` | valida, guarda y confirma política por quórum |
| `POST /api/profile` | cambia nombre visible y replica |
| `POST /api/profile/2fa/setup` | reautentica en NPM y prepara TOTP |
| `POST /api/profile/2fa/enable` | valida TOTP y genera diez códigos |
| `DELETE /api/profile/2fa/setup` | cancela el alta pendiente |
| `POST /api/profile/2fa/disable` | reautentica, valida TOTP y desactiva |
| `POST /api/profile/2fa/recovery-codes` | regenera códigos tras reautenticación |
| `POST /api/renovar/{id}` | reserva cuota, emite, activa y replica |
| `POST /api/sincronizar` | sincroniza o recupera automáticamente desde la única fuente lógica |
| `POST /api/sincronizar?forzar=true` | impone el activo; puede perder datos |
| `POST /api/revisar` | ejecuta vigilancia ahora |
| `POST /api/revisar?forzar=true` | añade aviso de prueba |

`POST /api/profile/password` devuelve `PASSWORD_MANAGED_BY_NPM`: la contraseña
se cambia en NPM.

### Configuración

```json
{
  "sync": {"enabled": true, "cron": "*/15 * * * *"},
  "namecheap": {
    "enabled": false,
    "api_user": "",
    "api_key": null,
    "clear_api_key": false
  },
  "renewal": {
    "days_before_expiry": 35,
    "warning_days": 15,
    "max_automatic_attempts": 4
  },
  "npm_api": {
    "user": "",
    "password": null,
    "clear_password": false,
    "port": 443,
    "https_port": 443,
    "timeout_seconds": 720
  }
}
```

Vacío o `null` conserva el secreto. Las banderas `clear_*` lo borran de forma
deliberada. No se admiten campos desconocidos ni booleanos como texto.

## Resultado de quórum

Operaciones distribuidas pueden incluir:

```json
{
  "ok": true,
  "complete": false,
  "acknowledged": 2,
  "cluster_size": 3,
  "quorum": 2,
  "resultados": {
    "node-b": {"ok": true},
    "node-c": {"ok": false, "error": "..."}
  }
}
```

`ok` indica mayoría; `complete` indica todos. Un cliente no debe convertir
`complete=false` en éxito total ni asumir que el nodo ausente está actualizado.

## Resultado de renovación

El cliente debe distinguir:

- petición no enviada por autoridad, cuota o ledger sin quórum;
- resultado indeterminado, pendiente de reconciliar;
- PEM emitido pero TLS pendiente;
- TLS correcto pero snapshot o ledger pendientes de quórum;
- renovación completa.

`emision_ok=true` no basta. La condición completa exige fingerprint guardado
nuevo, TLS exacto en todos los consumidores y confirmación de snapshot y ledger
por mayoría. Los estados pendientes no autorizan otra emisión inmediata.

## API interna

Protocolo interno versión `1`, no destinado a terceros:

| Método y ruta | Uso |
| --- | --- |
| `GET /api/internal/local` | salud y revisiones locales |
| `GET /api/internal/inventario` | huellas de NPM |
| `GET /api/internal/export` | snapshot estable solicitado por el activo a la fuente lógica |
| `GET /api/internal/state` | configuración y ledger para el activo firmado |
| `POST /api/internal/config` | paquete esquema `2` de configuración y ledger |
| `POST /api/internal/receive` | snapshot NPM cifrado |

Cabeceras: `X-NPMG-Protocol`, `X-NPMG-Source`, `X-NPMG-Target`,
`X-NPMG-Timestamp`, `X-NPMG-Nonce` y `X-NPMG-Signature`.

HMAC liga método, ruta, origen, destino, instante, nonce y body hash. AES-GCM
cifra cuerpos y respuestas y las liga al contexto. Los nonces de escritura se
persisten para impedir replay tras reinicio. El token compartido nunca viaja.

No reutilices `NPMG_CLUSTER_TOKEN` como token de automatización. La versión no
ofrece credenciales API externas para mutaciones.

## Keepalived/floating-ip

Respuesta esperada:

```json
{
  "direcciones": [
    {
      "servicio": "npm",
      "estado": "en_uso",
      "portador": "node-a",
      "ip": "<ip-flotante>"
    }
  ]
}
```

Guardian sólo consulta. HTTPS verifica el almacén del sistema o
`NPMG_KEEPALIVED_CA_FILE`; HTTP requiere
`NPMG_ALLOW_INSECURE_KEEPALIVED_API=1`. Si se configura
`NPMG_KEEPALIVED_API_TOKEN` o `NPMG_KEEPALIVED_API_TOKEN_FILE`, Guardian lo envía como
`Authorization: Bearer …`; la clave sólo necesita `status:read` y nunca aparece en respuestas
ni registros de estado.

## Nginx Proxy Manager

Identidad humana:

- `POST /api/tokens`;
- `GET /api/users/me`.

Renovación técnica:

- `POST /api/tokens`;
- `POST /api/nginx/certificates/{id}/renew`.

`NPMG_NPM_API_SCHEME=https`, puerto `443` y validación de CA son los valores
seguros iniciales. HTTP 81 exige `NPMG_ALLOW_INSECURE_NPM_API=1`.

La verificación TLS lee el PEM guardado y consulta todos los dominios activos
asociados en `proxy_host`, `redirection_host` y `dead_host`. Compara el
fingerprint DER SHA-256 exacto, no sólo la fecha.

## Namecheap

La API XML se usa para comprobar IP y credenciales. Guardian no modifica la
lista blanca. La integración puede desactivarse y sólo condiciona DNS-01
Namecheap; no degrada snapshots, HTTP-01 ni otros proveedores.

## Docker

Por el socket Unix, Guardian sólo puede:

- inspeccionar el contenedor configurado;
- detenerlo y arrancarlo durante una réplica;
- ejecutar las órdenes fijas de validación y recarga de Nginx.

No existe un endpoint de shell o comando arbitrario.

## Notificaciones

Los mounts opcionales de Unraid permiten escribir eventos para la cola y agentes
del host. Fuera de Unraid, su ausencia no impide la función principal. Guardian
no incorpora webhooks privados de una instalación en la imagen.

## Códigos HTTP relevantes

| Código | Caso habitual |
| --- | --- |
| `401` | sesión, credenciales, token NPM o protocolo interno inválido |
| `403` | CSRF ausente o cuenta sin autorización |
| `404` | ruta, certificado o recurso inexistente |
| `409` | rol incorrecto, replay, conflicto, operación ocupada o estado 2FA |
| `413` | snapshot sobre el límite |
| `422` | JSON, cron, rango o contrato inválido |
| `426` | login o mutación sin HTTPS confiable |
| `429` | límite temporal de login |
| `502` | respuesta NPM inválida |
| `503` | NPM, Docker, autoridad o quórum no disponibles |
