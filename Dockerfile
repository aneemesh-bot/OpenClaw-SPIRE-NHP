FROM python:3.14-slim

WORKDIR /app

# Build tools needed to compile libtropic01_bridge.so
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    libusb-1.0-0-dev \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the C library source and build the bridge shared library
COPY tropic01-req/libtropic/ tropic01-req/libtropic/
COPY tropic01-req/libtropic_bridge/ tropic01-req/libtropic_bridge/
RUN cmake -S tropic01-req/libtropic_bridge \
          -B tropic01-req/libtropic_bridge/build \
          -DCMAKE_BUILD_TYPE=Release && \
    cmake --build tropic01-req/libtropic_bridge/build --parallel

COPY nhp_daemon/ nhp_daemon/
COPY tests/ tests/

RUN mkdir -p /var/run/spire-nhp

ENV SPIRE_NHP_SOCKET=/var/run/spire-nhp/workload.sock
ENV SPIRE_NHP_DB=/var/run/spire-nhp/spire_nhp.db
ENV SPIRE_NHP_LOG_DB=/var/run/spire-nhp/spire_nhp_log.db

# Web admin portal — bind to all interfaces inside the container.
# Override SPIRE_NHP_WEB_HOST/PORT at runtime as needed.
ENV SPIRE_NHP_WEB_HOST=0.0.0.0
ENV SPIRE_NHP_WEB_PORT=8080

EXPOSE 8080

CMD ["python", "-m", "nhp_daemon"]
