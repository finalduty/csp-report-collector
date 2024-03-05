# csp-report-collector
Content Security Policy Report Collector


Python Flask App to receive and store CSP violation reports from browsers.

## Configuration
The CSP Report Collector is configurable via file and environment variables. Loading environment variables from .env files are also supported.

The configuration file must be called `settings.conf`.

Environment variables take precedence over options specified in the config file.

ENVVAR | Config File | Example | Description
---|---|---|---
`CSPRC_DB_URI` | `db_uri` | `mariadb://localhost:3306/csp_reports` | Full database connection string. e.g. `sqlite://db.sqlite`
`CSPRC_DB_TYPE` | `db_type` | `sqlite`, `mariadb`, `mssql`, `postgresql` | The Type of database to use
`CSPRC_DB_HOST` | `db_host` | `localhost`, `127.0.0.1` | The hostname or IP address of the database server
`CSPRC_DB_PORT` | `db_port` | `1433`, `3306`, `5432` | The port of the database server. May be left blank to use the default for the db_type.
`CSPRC_DB_USERNAME` | `db_username` | `user` | The username to authenticate to the db server with
`CSPRC_DB_PASSWORD` | `db_password` | `correcthorsebatterystaple` | The password to authenticate to the db server with
`CSPRC_DB_NAME` | `db_name` | `csp_reports` |

You may specify the db connection string as a single `db_uri` entry, or through a combination of `db_uri` and other options.

### Examples
Using DB_URI Only:

    export CSPRC_DB_URI="mariadb://username:password@localhost:3306/csp_reports

Using a combination of DB_URI and individual options:

    export CSPRC_DB_URI="mariadb://localhost:3306"
    export CSPRC_DB_USERNAME="username"
    export CSPRC_DB_PASSWORD="password"
    export CSPRC_DB_NAME="csp_reports"

## How to use
It is recommended to use the [finalduty/csp-report-collector](https://hub.docker.com/r/finalduty/csp-report-collector) container from Dockerhub, but you may also build a container from the [Dockerfile](Dockerfile), or install the app locally using pipenv.

The app does not currently support TLS, and so it is recommended to run it behind a TLS Proxy such as Nginx or Traefik.

```
## Start container
docker run -d --rm -p 8000:8000 -e CSPRC_DB_URI="sqlite:///db.sqlite" --name csp_report_collector finalduty/csp_report_collector

## Check the status endpoint, this should return a 200
curl http://localhost:8000/status

## Submit a test CSP Report, this should return a 204
curl -X POST http://localhost:8000/ -H 'Content-Type: application/csp-report' --data-binary '{"csp-report":{"document-uri":"https://domain.evil/","referrer":"","violated-directive":"frame-ancestors","effective-directive":"frame-ancestors","original-policy":"frame-ancestors *.domain.net;","disposition":"enforce","blocked-uri":"https://domain.evil/","status-code":0,"script-sample":""}}'

## Stop container
docker stop csp_report_collector
```

## License
[MIT License](LICENSE)
