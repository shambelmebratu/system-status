FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/northstar-agent
COPY agent/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/agent.py ./agent.py

EXPOSE 9100
# Push mode (NORTHSTAR_URL set) has no listener to probe; pull mode serves /health.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import os, urllib.request; os.getenv('NORTHSTAR_URL') or urllib.request.urlopen('http://127.0.0.1:9100/health', timeout=2)"
CMD ["python", "agent.py"]
