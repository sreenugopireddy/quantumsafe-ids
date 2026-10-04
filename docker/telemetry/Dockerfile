ARG TELEMETRY_IMAGE_PYTHON=python:3.11-slim
FROM ${TELEMETRY_IMAGE_PYTHON}
RUN pip install --no-cache-dir docker==7.1.0
COPY collector.py /collector.py
ENTRYPOINT ["python", "/collector.py"]