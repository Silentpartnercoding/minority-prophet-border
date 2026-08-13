FROM python:3.12-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

WORKDIR /app

RUN addgroup --system sandbox && adduser --system --ingroup sandbox sandbox
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY border ./border
RUN pip install --no-cache-dir ".[sandbox]"

RUN mkdir -p /data && chown sandbox:sandbox /data
USER sandbox

EXPOSE 8080
CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${PORT} --workers 1 --threads 8 --access-logfile - --error-logfile - border.wsgi:app"]
