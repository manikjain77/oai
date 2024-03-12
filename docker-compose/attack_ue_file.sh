#!/bin/bash

interval=20
while true; do
    # Run the docker-compose command
    docker-compose -f docker-compose-ueransim-vpp.yaml up -d
    sleep 1
    docker-compose -f docker-compose-ueransim-vpp.yaml down
    # Sleep for the specified interval
    sleep $interval
done
