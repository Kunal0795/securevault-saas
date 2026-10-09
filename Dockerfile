FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# unprivileged user: no home directory, no login shell
RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

WORKDIR /app

# dependencies first: this layer stays cached until requirements.txt changes
COPY requirements.txt .
RUN pip install -r requirements.txt

# code stays root-owned: the app user can read it but not modify it
COPY . .

USER app
EXPOSE 8000

CMD ["gunicorn", "securevault.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3", "--worker-tmp-dir", "/dev/shm", "--access-logfile", "-", "--error-logfile", "-"]
