#!/bin/bash

ACTION=$1
OPTION=$2
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Function to remove old containers and images that are not used
cleanup() {
  echo "Removing old containers and images..."
  docker system prune -f
  if [ $? -ne 0 ]; then
    echo "${RED}ERROR:${NC} Failed to clean up Docker resources. Exiting..."
  else
    echo "${GREEN}SUCCESS:${NC} Cleanup completed."
  fi
}

start_app() {
  echo "Starting docker with app..."
  docker-compose --env-file .env -f docker/docker-compose.app.yml up --build -d
  if [ $? -ne 0 ]; then
    echo "${RED}ERROR:${NC} Failed to start the app. Exiting..."
  else
    echo "${GREEN}SUCCESS:${NC} App has been started."
  fi
}

stop_app() {
  echo "Stopping app..."
  docker-compose --env-file .env -f docker/docker-compose.app.yml down
  if [ $? -ne 0 ]; then
    echo "${RED}ERROR:${NC} Failed to stop app..."
  else
    echo "${GREEN}SUCCESS:${NC} App has been stopped."
  fi
}

case $ACTION in
  up)
    start_app
    ;;
  stop)
    stop_app
    ;;
  clean)
    cleanup
    ;;
  *)
    echo "${RED}INVALID COMMAND.${NC} Usage: $0 {up|stop|clean} [--app|--env|--all]"
    ;;
esac
