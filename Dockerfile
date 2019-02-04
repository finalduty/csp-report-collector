FROM alpine:3.9
MAINTAINER Andy Dustin <andy.dustin@touchpointgroup.com>

RUN apk update && apk upgrade && apk add python3 py3-gunicorn py3-pip
RUN pip3 -q install pymongo Flask
ADD main.py /app/main.py

EXPOSE 8000
WORKDIR /app
CMD ["/usr/bin/gunicorn", "--workers=2", "--bind=0.0.0.0", "--name=csp-endpoint", "main:app"]

