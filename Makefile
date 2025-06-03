.PHONY: run swagger docker-build docker-up docker-up-detached docker-down docker-stop

# Run the Go application with live reload using CompileDaemon
# Suitable for local development to see changes instantly
run:
	CompileDaemon -build="go build -o backend-self-pass-manager ./cmd" -command="./backend-self-pass-manager"

# Generate Swagger documentation based on annotations in main.go
swagger:
	swag init --generalInfo cmd/main.go --output docs

# Build and start Docker containers (forces rebuild)
# Use when you want to rebuild images, typically before deployment
docker-build:
	docker-compose up --build

# Start Docker containers in the foreground (logs shown in terminal)
# Recommended for local development to monitor container output
docker-up:
	docker-compose up

# Start Docker containers in detached mode (run in background)
# Recommended for production or staging environments
docker-up-detached:
	docker-compose up -d

# Stop and remove Docker containers, networks, and volumes
docker-down:
	docker-compose down

# Stop Docker containers without removing them (containers can be restarted later)
docker-stop:
	docker-compose stop
