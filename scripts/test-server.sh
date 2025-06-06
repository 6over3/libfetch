#!/bin/bash

# Docker HTTP Bin Runner Script
# Runs the go-httpbin container with proper port mapping

set -e  # Exit on any error

CONTAINER_NAME="httpbin-server"
IMAGE="ghcr.io/mccutchen/go-httpbin"
HOST_PORT="8080"
CONTAINER_PORT="8080"

# Function to check if container is already running
check_container() {
    if docker ps -q -f name="$CONTAINER_NAME" | grep -q .; then
        return 0  # Container is running
    else
        return 1  # Container is not running
    fi
}

# Function to stop existing container
stop_container() {
    echo "Stopping existing container..."
    docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
    docker rm "$CONTAINER_NAME" >/dev/null 2>&1 || true
}

# Function to start the container
start_container() {
    echo "Starting HTTP Bin server..."
    docker run -d \
        --name "$CONTAINER_NAME" \
        -p "$HOST_PORT:$CONTAINER_PORT" \
        "$IMAGE"
    
    echo "HTTP Bin server started successfully!"
    echo "Access it at: http://localhost:$HOST_PORT"
}

# Main logic
main() {
    echo "Docker HTTP Bin Server Manager"
    echo "=============================="
    
    # Check if Docker is running
    if ! docker info >/dev/null 2>&1; then
        echo "Error: Docker is not running or not accessible"
        exit 1
    fi
    
    # Check if container is already running
    if check_container; then
        echo "Container '$CONTAINER_NAME' is already running"
        echo "Access it at: http://localhost:$HOST_PORT"
        echo ""
        read -p "Do you want to restart it? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            stop_container
            start_container
        else
            echo "Container left running"
        fi
    else
        # Stop any existing stopped container with the same name
        if docker ps -a -q -f name="$CONTAINER_NAME" | grep -q .; then
            echo "Removing stopped container with same name..."
            docker rm "$CONTAINER_NAME" >/dev/null 2>&1 || true
        fi
        
        # Pull latest image
        echo "Pulling latest image..."
        docker pull "$IMAGE"
        
        # Start the container
        start_container
    fi
}

# Handle script arguments
case "${1:-}" in
    start)
        start_container
        ;;
    stop)
        stop_container
        echo "Container stopped and removed"
        ;;
    restart)
        stop_container
        start_container
        ;;
    status)
        if check_container; then
            echo "Container '$CONTAINER_NAME' is running"
            echo "Access it at: http://localhost:$HOST_PORT"
        else
            echo "Container '$CONTAINER_NAME' is not running"
        fi
        ;;
    logs)
        docker logs -f "$CONTAINER_NAME"
        ;;
    *)
        if [ $# -eq 0 ]; then
            main
        else
            echo "Usage: $0 [start|stop|restart|status|logs]"
            echo ""
            echo "Commands:"
            echo "  start   - Start the HTTP Bin container"
            echo "  stop    - Stop and remove the container"
            echo "  restart - Restart the container"
            echo "  status  - Check container status"
            echo "  logs    - Follow container logs"
            echo ""
            echo "Run without arguments for interactive mode"
        fi
        ;;
esac