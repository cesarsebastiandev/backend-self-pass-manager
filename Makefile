.PHONY: run swagger

run:
	CompileDaemon -build="go build -o backend-self-pass-manager ./cmd" -command="./backend-self-pass-manager"

swagger:
	swag init --generalInfo cmd/main.go --output docs


