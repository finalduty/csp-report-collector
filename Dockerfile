FROM alpine:3.23

ENV PATH=/root/.local/bin:$PATH
ENV PIPENV_VENV_IN_PROJECT=1
WORKDIR /app

COPY .flaskenv Pipfile Pipfile.lock src/* /app/
RUN adduser -h /app -D -H -g "CSP Report Collector" csprc \
  && apk add --no-cache --update \
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
  && pip3 install --break-system-packages --user pipenv \
  && chown -Rc csprc:csprc /app \
  && /root/.local/bin/pipenv install --deploy

USER csprc
EXPOSE 8000
HEALTHCHECK CMD curl -fs localhost:8000/status
CMD [".venv/bin/gunicorn", "--workers=2", "--bind=0.0.0.0:8000", "--name=csprc", "--access-logfile=-", "csp_report_collector:app"]
