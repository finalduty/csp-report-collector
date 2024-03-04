FROM alpine:3.17

WORKDIR /app

RUN apk add --update \
  python3-dev \
  py3-pip \
  gcc \
  g++ \
  libpq-dev \
  musl-dev \
  mariadb-dev \
  unixodbc-dev \
  postgresql \
  && rm -rf /var/cache/apk/*
RUN pip3 install --user pipenv

ADD Pipfile Pipfile.lock src/* /app/

RUN /root/.local/bin/pipenv install --deploy

EXPOSE 8000
CMD ["/usr/bin/gunicorn", "--workers=2", "--bind=0.0.0.0:8000", "--name=csprc", "csp_report_collector"]
