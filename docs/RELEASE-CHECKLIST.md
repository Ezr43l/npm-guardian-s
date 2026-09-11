# Checklist de publicacion de NPM Guardian 1.0.4

Este repositorio contiene únicamente el árbol público aprobado de NPM Guardian.
El historial y la infraestructura del entorno de desarrollo no forman parte de
la distribución compartida.

## Puertas pendientes

- [ ] Ejecutar externamente `PUT` + `GET /repos/{owner}/{repo}/immutable-releases`
  con permisos de administracion y, solo tras confirmar `enabled=true`, fijar
  `IMMUTABLE_RELEASES_ENABLED=true`. El workflow no almacena ningun PAT y
  comprueba de nuevo `immutable=true` tras publicar.

- [x] Adoptar Apache-2.0 y añadir el texto canónico en `LICENSE`.
- [ ] Configurar la variable del repositorio público `LICENSE_SPDX=Apache-2.0`.
- [x] Aprobar expresamente la creacion de `Ezr43l/npm-guardian-s`.
- [ ] Exportar un arbol limpio sin remotos, ramas ni historial privados.
- [ ] Publicar `ghcr.io/ezr43l/npm-guardian-s:1.0.4` para AMD64/ARM64
  con SBOM, procedencia y digest.
- [ ] Verificar pull anonimo y todos los enlaces de la plantilla publica.
- [ ] Ejecutar Trivy y Gitleaks de nuevo sobre el artefacto exportado.
- [x] Probar tres hosts Unraid reales con NPM y Keepalived: quorum 2/3,
  replica completa, failover, nodo aislado y regreso. La evidencia con datos de
  infraestructura se conserva fuera del árbol compartible.
- [x] Probar backup y restauracion conjunta de datos NPM, Certbot y `/datos`,
  incluidos sus secretos generados, preservando propietarios numericos, modos, xattrs y
  ACL cuando el filesystem lo permite.
- [ ] Repetir bootstrap desde cero y conflicto deliberado en un laboratorio
  desechable; no se altera la base NPM autoritativa para satisfacer esta puerta.
- [ ] Validar el perfil HTTPS completo con CA publica y privada.
- [x] Definir y ejecutar la matriz inicial: NPM `2.15.1` verificado con Guardian
  ARM64 y AMD64; versiones anteriores no se soportan y cada parche posterior
  debe superar el mismo laboratorio antes de incorporarse.
- [x] Mantener una sola plantilla y un solo contenedor; `docker.sock` se monta
  únicamente en NPM Guardian y el cliente aplica una lista blanca al NPM configurado.
- [ ] Instalar desde cero usando solo artefactos y documentacion publicos.

## Contrato inmutable de esta release

1. La version permanece exactamente `1.0.4` en `VERSION`, imagen, Compose,
   panel y plantilla.
2. No se crea ni publica ningun artefacto desde el repositorio privado.
3. La plantilla publica no contiene valores de una instalacion y apunta a
   `Ezr43l/npm-guardian-s`.
4. La instalacion nueva no depende de un Registry local; un mirror interno es
   un override opcional.
5. El workflow rechaza licencia ausente, tag divergente, repositorio incorrecto,
   dependencias auditadas o codigo inseguro y cualquier vulnerabilidad
   critica/alta detectada, sin `ignore-unfixed`.
6. El tag `v1.0.4` es anotado y protegido, exige CI correcta sobre el mismo
   commit y produce SBOM por arquitectura, digest y procedencia firmada.
7. La plantilla contiene exactamente cinco campos Docker; la instalación nueva
   se termina desde el asistente web y no requiere secretos externos.
