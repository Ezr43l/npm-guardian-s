# syntax=docker/dockerfile:1.7
# Imagen portable de NPM Guardian. La fase de pruebas nunca llega a la imagen
# final, pero impide publicar un artefacto cuyo codigo no supere la suite.
ARG PYTHON_IMAGE=python:3.12-alpine@sha256:d09d15e60962ca365d1cd544a48773bac9d33f2fb1b00f2aa0deec78ade7dc31
FROM ${PYTHON_IMAGE} AS runtime-base

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
RUN pip install --no-cache-dir --only-binary=:all: --requirement /tmp/requirements.txt

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
WORKDIR /src
COPY . /src
RUN export NPMG_SESSION_SECRET="$(head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n')" && \
    export NPMG_CLUSTER_TOKEN="$(head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n')" && \
    export NPMG_STANDALONE=1 NPMG_NODE_NAME=image-test-node && \
    python3 -m unittest discover -s tests -v && touch /tmp/tests-passed

FROM runtime-base AS runtime
COPY --from=tests /tmp/tests-passed /opt/tests-passed
EXPOSE 6061

# El endpoint GET /api/health permite comprobar el proceso desde fuera sin
# depender de docker exec. El orquestador es quien decide la politica de salud.
ENTRYPOINT ["python3", "/opt/panel/arranque.py"]
