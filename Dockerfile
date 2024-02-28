FROM alpine:3.19
WORKDIR /opt/

RUN apk add --update \
  python3 \
  python3-dev \
  py3-pip \
  gcc \
  musl-dev \
  && rm -rf /var/cache/apk/*

COPY src /app

RUN pip3 install --user --break-system-packages pipenv

EXPOSE 8000
CMD ["/usr/bin/gunicorn", "--workers=2", "--bind=0.0.0.0:8000", "--name=csprc", "csp_report_collector"]
