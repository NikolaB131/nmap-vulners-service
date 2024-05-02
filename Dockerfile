FROM golang:1.22-alpine

RUN apk add make

COPY . /app

WORKDIR /app

RUN make build-linux

CMD ["./build/bin/app", "-c", "./config.yml", "--vscript", "./scripts/vulners.nse"]
