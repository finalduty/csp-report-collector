FROM alpine:3.9
MAINTAINER Andy Dustin <andy.dustin@touchpointgroup.com>

RUN apk add --update \
    python3 \
    python3-dev \
    py3-pip \
    gcc \
    musl-dev \
  && rm -rf /var/cache/apk/*

COPY . .
COPY settings.conf.example settings.conf

RUN pip3 install -U pip
RUN pip3 install -r requirements.txt

EXPOSE 8000
CMD ["/usr/bin/gunicorn", "--workers=2", "--bind=0.0.0.0:8000", "--name=csp-endpoint", "main:app"]
