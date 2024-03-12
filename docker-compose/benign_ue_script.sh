#!/bin/bash

# Define the command to be executed
command_to_run="docker-compose -f docker-compose-benign_ueransim-vpp.yaml up -d"
command_to_run2="docker-compose -f docker-compose-benign_ueransim-vpp.yaml down"

# Define the interval in seconds
interval=60  # Change this value to your desired interval

# Calculate the total number of iterations (10 minutes / interval)
total_iterations=$((10 * 60 / interval))

# Loop for the specified number of iterations
for ((i = 0; i < total_iterations; i++)); do
    # Run the command
    $command_to_run
    sleep 1
    $command_to_run2
    # Wait for the defined interval
    sleep $interval
done
