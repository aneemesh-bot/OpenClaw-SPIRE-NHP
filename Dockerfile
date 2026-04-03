FROM python:3.14-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY nhp_daemon/ nhp_daemon/
COPY tests/ tests/

RUN mkdir -p /var/run/spire-nhp

ENV SPIRE_NHP_SOCKET=/var/run/spire-nhp/workload.sock
ENV SPIRE_NHP_DB=/var/run/spire-nhp/spire_nhp.db
ENV SPIRE_NHP_LOG_DB=/var/run/spire-nhp/spire_nhp_log.db

CMD ["python", "-m", "nhp_daemon"]
