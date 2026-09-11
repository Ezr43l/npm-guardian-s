# Pruebas del guardián

Se ejecutan dentro de la imagen ya construida: así se valida exactamente el
código y las dependencias que llegarán a los servidores. No necesitan red ni
datos reales de NPM.

```sh
scp -i <clave> docker/guardian/pruebas/*.py root@<nodo>:/tmp/
ssh -i <clave> root@<nodo> "
  docker run --rm --entrypoint python3 -v /tmp/replica.py:/p.py:ro ghcr.io/ezr43l/npm-guardian-s:1.0.4 /p.py
  docker run --rm --entrypoint python3 -v /tmp/comparar.py:/p.py:ro ghcr.io/ezr43l/npm-guardian-s:1.0.4 /p.py
  docker run --rm --entrypoint python3 -v /tmp/vigilancia.py:/p.py:ro ghcr.io/ezr43l/npm-guardian-s:1.0.4 /p.py
"
```

`--entrypoint python3` evita arrancar el servidor web de la imagen.

- `comparar.py` comprueba el arbitraje de inventarios iguales, altas,
  renovaciones, borrados y cambios divergentes.
- `replica.py` genera una SQLite real y verifica snapshot, manifiesto, huellas,
  rutas, enlaces, rol pasivo, lista blanca Docker y rotación de copias.
- `vigilancia.py` conserva las regresiones de autoridad, reintentos y cuota que
  podrían provocar emisiones duplicadas.

Los scripts escriben `ALL GOOD`/`TODO BIEN` o un fallo y devuelven 0 o 1.
