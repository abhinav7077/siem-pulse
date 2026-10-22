# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
# SIEM Pulse container: checks on a schedule + dashboard on :8080
#
#   docker build -t siem-pulse .
#   docker run -d -p 127.0.0.1:8080:8080 --env-file .env \
#     -v "$PWD/config.yaml:/etc/siem-pulse/config.yaml:ro" \
#     -v "$PWD/devices.xlsx:/etc/siem-pulse/sample_devices.xlsx:ro" \
#     -v siem-pulse-data:/data siem-pulse
#
# /etc/siem-pulse holds config + inventory (read-only); /data holds the SQLite
# history, reports and logs (keep it on a volume).
#
# Behind a TLS-inspecting proxy, pass its CA so pip can reach PyPI:
#   docker build --secret id=pip_ca,src=corp-ca.pem -t siem-pulse .

FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY siem_pulse ./siem_pulse
RUN --mount=type=secret,id=pip_ca,required=false \
    if [ -f /run/secrets/pip_ca ]; then export PIP_CERT=/run/secrets/pip_ca; fi \
 && pip wheel --no-cache-dir --no-deps --wheel-dir /wheels . \
 && pip wheel --no-cache-dir --wheel-dir /wheels pandas openpyxl pyyaml requests schedule python-dotenv

FROM python:3.12-slim
LABEL org.opencontainers.image.title="SIEM Pulse" \
      org.opencontainers.image.description="Log source health monitor for SOC and MSSP teams" \
      org.opencontainers.image.source="https://github.com/abhinav7077/siem-pulse" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN useradd --create-home --uid 10001 siempulse \
 && mkdir -p /data /etc/siem-pulse \
 && chown siempulse:siempulse /data
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels

# Demo defaults (mock mode); mount your own over these
COPY config.yaml sample_devices.xlsx /etc/siem-pulse/

USER siempulse
WORKDIR /data
ENV PYTHONUNBUFFERED=1
EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=60s --timeout=5s --start-period=60s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status == 200 else 1)"

ENTRYPOINT ["siem-pulse", "--config", "/etc/siem-pulse/config.yaml"]
CMD ["--schedule", "--dashboard", "--host", "0.0.0.0"]
