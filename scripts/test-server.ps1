# Docker HTTP Bin Runner Script (PowerShell)
# Runs the go-httpbin container with proper port mapping

param(
    [string]$Command = ""
)

$ErrorActionPreference = "Stop"

$CONTAINER_NAME = "httpbin-server"
$IMAGE = "ghcr.io/mccutchen/go-httpbin"
$HOST_PORT = "8080"
$CONTAINER_PORT = "8080"

# Function to check if container is already running
function Test-ContainerRunning {
    try {
        $runningContainers = docker ps -q -f "name=$CONTAINER_NAME" 2>$null
        return ![string]::IsNullOrEmpty($runningContainers)
    }
    catch {
        return $false
    }
}

# Function to stop existing container
function Stop-Container {
    Write-Host "Stopping existing container..."
    try {
        docker stop $CONTAINER_NAME 2>$null | Out-Null
    }
    catch {
        # Container might not exist, ignore error
    }
    try {
        docker rm $CONTAINER_NAME 2>$null | Out-Null
    }
    catch {
        # Container might not exist, ignore error
    }
}

# Function to start the container
function Start-Container {
    Write-Host "Starting HTTP Bin server..."
    docker run -d --name $CONTAINER_NAME -p "${HOST_PORT}:${CONTAINER_PORT}" $IMAGE
    
    Write-Host "HTTP Bin server started successfully!"
    Write-Host "Access it at: http://localhost:$HOST_PORT"
}

# Function to check if Docker is accessible
function Test-DockerAvailable {
    try {
        docker info 2>$null | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

# Main logic
function Start-Main {
    Write-Host "Docker HTTP Bin Server Manager (PowerShell)"
    Write-Host "============================================="
    
    # Check if Docker is running
    if (-not (Test-DockerAvailable)) {
        Write-Error "Error: Docker is not running or not accessible"
        exit 1
    }
    
    # Check if container is already running
    if (Test-ContainerRunning) {
        Write-Host "Container '$CONTAINER_NAME' is already running"
        Write-Host "Access it at: http://localhost:$HOST_PORT"
        Write-Host ""
        $reply = Read-Host "Do you want to restart it? (y/N)"
        if ($reply -match "^[Yy]$") {
            Stop-Container
            Start-Container
        }
        else {
            Write-Host "Container left running"
        }
    }
    else {
        # Stop any existing stopped container with the same name
        try {
            $stoppedContainers = docker ps -a -q -f "name=$CONTAINER_NAME" 2>$null
            if (![string]::IsNullOrEmpty($stoppedContainers)) {
                Write-Host "Removing stopped container with same name..."
                docker rm $CONTAINER_NAME 2>$null | Out-Null
            }
        }
        catch {
            # Ignore errors
        }
        
        # Pull latest image
        Write-Host "Pulling latest image..."
        docker pull $IMAGE
        
        # Start the container
        Start-Container
    }
}

# Handle script arguments
switch ($Command.ToLower()) {
    "start" {
        Start-Container
    }
    "stop" {
        Stop-Container
        Write-Host "Container stopped and removed"
    }
    "restart" {
        Stop-Container
        Start-Container
    }
    "status" {
        if (Test-ContainerRunning) {
            Write-Host "Container '$CONTAINER_NAME' is running"
            Write-Host "Access it at: http://localhost:$HOST_PORT"
        }
        else {
            Write-Host "Container '$CONTAINER_NAME' is not running"
        }
    }
    "logs" {
        docker logs -f $CONTAINER_NAME
    }
    "" {
        Start-Main
    }
    default {
        Write-Host "Usage: .\test-server.ps1 [start|stop|restart|status|logs]"
        Write-Host ""
        Write-Host "Commands:"
        Write-Host "  start   - Start the HTTP Bin container"
        Write-Host "  stop    - Stop and remove the container"
        Write-Host "  restart - Restart the container"
        Write-Host "  status  - Check container status"
        Write-Host "  logs    - Follow container logs"
        Write-Host ""
        Write-Host "Run without arguments for interactive mode"
    }
} 