.PHONY: run swagger docker-build docker-up docker-up-detached docker-down docker-stop

# Compile Go backend for Windows, Linux and MacOS (64-bit) producing a standalone .exe
build-win:
	GOOS=windows GOARCH=amd64 go build -o dist/self-pass-manager.exe ./cmd

build-linux:
	GOOS=linux GOARCH=amd64 go build -o self-pass-manager ./cmd

build-mac:
	GOOS=darwin GOARCH=amd64 go build -o self-pass-manager ./cmd


# Run the Go application with live reload using CompileDaemon
# Suitable for local development to see changes instantly
run:
	CompileDaemon -build="go build -o backend-self-pass-manager ./cmd" -command="./backend-self-pass-manager"

# Generate Swagger documentation based on annotations in main.go
swagger:
	swag init --generalInfo cmd/main.go --output docs

