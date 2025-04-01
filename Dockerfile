# syntax=docker/dockerfile:1-labs
FROM alpine:3.20 AS build
WORKDIR /app
ENV PIPENV_VENV_IN_PROJECT=1

RUN apk add --update \
	python3-dev \
	py3-pip \
	curl \
	gcc \
	g++ \
	libpq-dev \
	musl-dev \
	mariadb-dev \
	unixodbc-dev

COPY Pipfile Pipfile.lock /app/
RUN pip3 install --break-system-packages pipenv && \
	pipenv install --deploy


FROM alpine:3.20
WORKDIR /app

RUN adduser -h /app -D -H -g "CSP Report Collector" csprc
RUN apk add --update --no-cache \
  python3 \
  libpq-dev \
  mariadb-dev \
  unixodbc-dev 
COPY --from=build /app/ /app/
COPY .flaskenv src/*.py /app/
COPY --parents src/./templates/* /app/
COPY --parents src/./static/* /app/
RUN chown -Rc csprc:csprc /app

USER csprc
EXPOSE 8000
HEALTHCHECK CMD curl -fs localhost:8000/status
CMD ["/app/.venv/bin/gunicorn", "--workers=2", "--bind=0.0.0.0:8000", "--name=csprc", "--access-logfile=-", "csp_report_collector:app"]
