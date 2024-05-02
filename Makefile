BINARYFILE=./build/bin/app
SOURCEFILE=./cmd/app/main.go
SERVICE_NAME=nmap-vulners-service
MOCK_VULN_SERVER_NAME=mock-vulnhub-server

build: $(SOURCEFILE)
	go build -o $(BINARYFILE) $(SOURCEFILE)

build-linux: $(SOURCEFILE)
	GOOS=linux go build -o $(BINARYFILE) $(SOURCEFILE)

run: build
	$(BINARYFILE) -c ./config.yml --vscript ./scripts/vulners.nse

clean:
	rm $(BINARYFILE)

generate-proto:
	protoc \
		--go_out . --go_opt paths=source_relative \
		--go-grpc_out . --go-grpc_opt paths=source_relative \
		./pkg/proto/nmap-vulners-service.proto

test:
	go test ./tests/... -v

lint:
	gofmt -s -w .

docker-mock-vuln-server:
		docker rm -f -v $(MOCK_VULN_SERVER_NAME)
		cd ./tests/mock-vuln-server && \
		docker run -d --privileged --name $(MOCK_VULN_SERVER_NAME) \
			-p 11001:2222 \
			-p 11002:8080 \
			docker:dind && \
		docker cp ./startup.sh $(MOCK_VULN_SERVER_NAME):/startup.sh
		docker exec $(MOCK_VULN_SERVER_NAME) sh /startup.sh

docker-build:
	docker build --tag $(SERVICE_NAME) .

docker-run: docker-build
	docker run -d --name $(SERVICE_NAME) $(SERVICE_NAME)
