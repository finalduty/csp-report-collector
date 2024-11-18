FROM alpine:3.20

ENV PATH=/root/.local/bin:$PATH
ENV PIPENV_VENV_IN_PROJECT=1
WORKDIR /app

RUN adduser -h /app -D -H -g "CSP Report Collector" csprc
RUN apk add --update \
  python3-dev \
  py3-pip \
  curl \
  gcc \
  g++ \
  libpq-dev \
  musl-dev \
  mariadb-dev \
  unixodbc-dev \
  postgresql \
  && rm -rf /var/cache/apk/*
RUN pip3 install --user pipenv
ADD .flaskenv Pipfile Pipfile.lock src/* /app/
RUN chown -Rc csprc:csprc /app
RUN /root/.local/bin/pipenv install --deploy

USER csprc
EXPOSE 8000
HEALTHCHECK CMD curl -fs localhost:8000/status
CMD [".venv/bin/gunicorn", "--workers=2", "--bind=0.0.0.0:8000", "--name=csprc", "--access-logfile=-", "csp_report_collector:app"]
