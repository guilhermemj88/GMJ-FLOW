FROM debian:bookworm-slim

ENV PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        pmacct \
        python3 \
        python3-pip \
    && pip3 install --no-cache-dir --break-system-packages clickhouse-connect==0.8.14 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/gmj-flow

COPY nfacctd.conf /etc/pmacct/nfacctd.conf
COPY allow.lst /etc/pmacct/allow.lst
COPY parse_pmacct.py /opt/gmj-flow/parse_pmacct.py

RUN mkdir -p /var/spool/pmacct

EXPOSE 9995/udp

CMD ["nfacctd", "-f", "/etc/pmacct/nfacctd.conf"]