FROM alpine:3.9
MAINTAINER Andy Dustin <andy.dustin@touchpointgroup.com>

RUN apk add --update \
    python3 \
    python3-dev \
    py3-pip \
    gcc \
    musl-dev \
    openssl \
  && rm -rf /var/cache/apk/*

COPY . .
RUN pip3 install -U pip
RUN pip3 install -r requirements.txt

# Gen certs
RUN mkdir -p /etc/ssl/certs; \
    mkdir -p /etc/ssl/private; \
    openssl genrsa -out /etc/ssl/private/ssl-cert-snakeoil.key 2048; \
    cp /etc/ssl/private/ssl-cert-snakeoil.key /etc/ssl/private/ssl-cert-snakeoil.key.orig; \
    openssl rsa -in /etc/ssl/private/ssl-cert-snakeoil.key.orig -out /etc/ssl/private/ssl-cert-snakeoil.key; \
    openssl req -new -key /etc/ssl/private/ssl-cert-snakeoil.key -out /etc/ssl/certs/cert.csr -subj "/C=GB/ST=GB/L=London/O=DockerTest/OU=DockerTest/CN=DockerTest"; \
    openssl x509 -req -days 3650 -in /etc/ssl/certs/cert.csr -signkey /etc/ssl/private/ssl-cert-snakeoil.key -out /etc/ssl/certs/ssl-cert-snakeoil.pem

EXPOSE 8443
CMD ["/usr/bin/python3", "main.py"]
