ARG BASE_IMAGE=python:3.14-slim-bookworm
FROM ${BASE_IMAGE}

COPY emitter.py /opt/shieldchain-replay/emitter.py

ENTRYPOINT ["python", "/opt/shieldchain-replay/emitter.py"]
