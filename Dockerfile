FROM alpine:3.17 as base-image
RUN apk add --update --no-cache \
  python3 \
  python3-dev \
  py3-pip \
  gcc \
  musl-dev 


FROM base-image as builder
WORKDIR /app
ENV PIPENV_VENV_IN_PROJECT=1
RUN pip3 install pipenv
ADD Pipfile Pipfile.lock ./
RUN pipenv install --deploy


FROM base-image as final-image
WORKDIR /app
COPY --from=builder /app/.venv/ /app/.venv
ADD src/csp_report_collector.py /app

EXPOSE 8000
CMD [".venv/bin/python3", "-m", "gunicorn", "--workers=2", "--bind=0.0.0.0:8000", "--name=csp-endpoint", "csp_report_collector:app"]
