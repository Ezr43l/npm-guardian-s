# syntax=docker/dockerfile:1.7
# Imagen portable de NPM Guardian. La fase de pruebas nunca llega a la imagen
# final, pero impide publicar un artefacto cuyo codigo no supere la suite.
ARG PYTHON_IMAGE=python:3.12.16-alpine3.24@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89
FROM ${PYTHON_IMAGE} AS security-builder
COPY docker/security /security
RUN sh /security/build-runtime.sh

FROM ${PYTHON_IMAGE} AS security-python
RUN apk upgrade --no-cache && apk add --no-cache libexpat=2.10.0-r0 libgcc=15.2.0-r5
COPY --from=security-builder /out-runtime/ /
COPY --from=security-builder /wheels /tmp/security-wheels
COPY docker/security/install-python.py /tmp/install-python.py
RUN python3 -c 'import sys,pyexpat;assert sys.version_info[:3] == (3,12,16);assert pyexpat.version_info >= (2,10,0)'

FROM security-python AS runtime-base

ARG APP_VERSION
ARG VCS_REF="unknown"
ARG BUILD_DATE="unknown"
ARG LICENSE="Apache-2.0"
LABEL org.opencontainers.image.title="NPM Guardian" \
      org.opencontainers.image.description="Alta disponibilidad y replica coherente para Nginx Proxy Manager" \
      org.opencontainers.image.source="https://github.com/Ezr43l/npm-guardian-s" \
      org.opencontainers.image.url="https://github.com/Ezr43l/npm-guardian-s" \
      org.opencontainers.image.documentation="https://github.com/Ezr43l/npm-guardian-s/tree/main/docs" \
      org.opencontainers.image.licenses="${LICENSE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.version="${APP_VERSION}"

# Las dependencias Python se fijan como wheels para que el SBOM y Trivy vean
# sus versiones upstream exactas. Bash se conserva para el adaptador opcional
# de notificaciones de Unraid.
RUN apk upgrade --no-cache && \
    apk add --no-cache curl bash tzdata ca-certificates
COPY docker/guardian/requirements.txt /tmp/requirements.txt
RUN python3 -m pip install --no-cache-dir --upgrade pip==26.2.2 \
    && python3 /tmp/install-python.py /tmp/requirements.txt \
    && python3 -m pip uninstall --yes pip

COPY docker/guardian/panel /opt/panel
COPY VERSION /opt/APP_VERSION
COPY LICENSE /opt/LICENSE
RUN test -n "$APP_VERSION" && \
    test "$(tr -d ' \r\n' < /opt/APP_VERSION)" = "$APP_VERSION"

ENV NPMG_PORT=6061 \
    NPMG_WEB=/opt/panel/web \
    NPMG_NPM_DB=/npm/database.sqlite \
    NPMG_NPM_DATA=/npm \
    NPMG_NPM_LETSENCRYPT=/npm-letsencrypt \
    NPMG_DATA_DIR=/datos \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

FROM runtime-base AS tests
ARG RUN_BUILD_TESTS=0
WORKDIR /src
COPY . /src
RUN if [ "$RUN_BUILD_TESTS" = "1" ]; then \
      export NPMG_SESSION_SECRET="$(head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n')"; \
      export NPMG_CLUSTER_TOKEN="$(head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n')"; \
      export NPMG_STANDALONE=1 NPMG_NODE_NAME=image-test-node; \
      python3 -m unittest discover -s tests -v; \
    fi && touch /tmp/tests-passed

FROM runtime-base AS runtime
COPY --from=tests /tmp/tests-passed /opt/tests-passed
EXPOSE 6061

# El endpoint GET /api/health permite comprobar el proceso desde fuera sin
# depender de docker exec. El orquestador es quien decide la politica de salud.
ENTRYPOINT ["python3", "/opt/panel/arranque.py"]
