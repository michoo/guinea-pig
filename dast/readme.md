# Discovery test repos


## Install & run

```
npm install
npm start
```

## Nuclei

```
./nuclei -target http://localhost:3000 -severity "medium,high,critical" -silent
```

## Zap

```
docker run --network host -v $(pwd):/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://localhost:3000 -r report.html
docker run --network host -v $(pwd):/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py -t http://localhost:3000 -r report.html

docker run -network host  -t ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py -t http://localhost:3000 -f openapi -r report.html
```