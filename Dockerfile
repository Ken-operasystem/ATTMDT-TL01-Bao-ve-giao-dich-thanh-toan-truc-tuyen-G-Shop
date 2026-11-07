# Một image dùng chung cho firewall, app, gateway, bank, bastion, admin và tester.
# Mỗi service chạy một lệnh khác nhau trong docker-compose.yml.
FROM python:3.12-alpine

RUN apk add --no-cache nftables openssl openssh-server openssh-client \
        curl netcat-openbsd postgresql-client tini su-exec \
    && adduser -D -s /bin/sh ops \
    && adduser -D -H -s /sbin/nologin svc \
    && sed -i 's/^ops:!/ops:*/' /etc/shadow

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ /srv/app/
COPY gateway/ /srv/gateway/
COPY bank/ /srv/bank/
COPY firewall/ /srv/firewall/
COPY bastion/ /srv/bastion/
COPY tests/ /srv/tests/
COPY scripts/ /srv/scripts/

ENV PYTHONPATH=/srv/app PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["/sbin/tini", "--"]
