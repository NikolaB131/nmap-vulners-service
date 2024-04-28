BINARYFILE=./build/bin/app
SOURCEFILE=./cmd/app/main.go

build: $(SOURCEFILE)
	go build -o $(BINARYFILE) $(SOURCEFILE)

run: build
	$(BINARYFILE) -c ./config.yml

clean:
	rm $(BINARYFILE)

generate-proto:
	protoc \
		--go_out . --go_opt paths=source_relative \
		--go-grpc_out . --go-grpc_opt paths=source_relative \
		./pkg/proto/nmap-vulners-service.proto
