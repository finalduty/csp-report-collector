# csp-report-collector
Content Security Policy Report Collector


Python Flask App to receive CSP reports from browsers and store them in MongoDB.


## Python Dependencies
Python dependencies can be installed with: `pip3 -r requirements.txt`

## Tests

```
docker build . -t csp-report

docker run -it -d --rm -p 8000:8000 --name test_csp_report csp-report

# Health endpoint, should be a 200
curl http://localhost:5000/health

# Should be a 400
curl -X POST http://localhost:5000/

# Should be a 204
curl -X POST http://localhost:5000/ -H 'Content-Type: application/csp-report' --data-binary '{"csp-report":{"document-uri":"https://domain.evil/","referrer":"","violated-directive":"frame-ancestors","effective-directive":"frame-ancestors","original-policy":"frame-ancestors *.domain.net;","disposition":"enforce","blocked-uri":"https://domain.evil/","status-code":0,"script-sample":""}}'

docker stop test_csp_report

```

## Contributors ✨
Thanks to the following people for their contributions:
 - [Nicolas Béguier](https://github.com/nbeguier)


## License
[MIT License](LICENSE)
