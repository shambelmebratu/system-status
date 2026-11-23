FROM python:3.12-slim

# The API, the worker and the migrations run as an ordinary user (uid 10001, group 0), never root. Group 0 lets the bundled
# host agent (root) read the token file the API writes into the shared volume, without extra capabilities.
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --uid 10001 --gid 0 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin smwatch \
 && mkdir -p /shared && chown 10001:0 /shared && chmod 0770 /shared

WORKDIR /app
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY backend ./

USER 10001:0
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
