FROM python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 OMP_NUM_THREADS=2
WORKDIR /app
COPY requirements.lock .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY download.py model-sha256.json ./
RUN HF_HUB_OFFLINE=0 TRANSFORMERS_OFFLINE=0 python download.py
COPY server.py .
USER 10001:10001
EXPOSE 8001
HEALTHCHECK --interval=10s --start-period=60s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8001/health')"
CMD ["python","server.py"]
