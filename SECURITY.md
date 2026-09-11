# Seguridad

No publiques vulnerabilidades, credenciales ni datos de una instalacion en una
incidencia abierta. En el repositorio compartido utiliza **Security > Report a
vulnerability** para abrir un aviso privado de GitHub. Si ese canal no estuviera
disponible, contacta al mantenedor por un medio privado antes de compartir detalles.

Incluye version, arquitectura, forma de instalacion y pasos minimos de
reproduccion. No adjuntes `guardian.json`, bases SQLite, PEM, journals, cookies,
tokens de NPM o del cluster, secretos de sesion, claves API, TOTP ni claves SSH.

El portal debe publicarse mediante un proxy HTTPS de confianza. Restringe el
puerto interno a los miembros del cluster y protege tambien las API de NPM y
Keepalived con TLS verificable. NPM Guardian funciona en un único contenedor y
monta `docker.sock` para detener, arrancar y validar el NPM declarado durante
una réplica. El código aplica una lista blanca cerrada, pero controlar el
contenedor equivale a poder alcanzar el daemon Docker: limita el acceso al
portal, mantén la imagen actualizada y no amplíes las operaciones permitidas.
