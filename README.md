# Netstat-pid 

Netstat-pid is a binary the netstat network connection information.

* Display network connections from all processes including threads on a host by default.
* Display both hostname and container name if available.
* Displays network connections for a specific pid.

## How It Works

1. Traverses the entire process tree and each thread 
2. Reads connection information from proc files tcp and tcp6.
3. Outputs the connection information as JSON to stdout.

## Usage

<details><summary><b>Show instructions</b></summary>

1. List connections for a specific PID:

    ```sh
    ./netstat-pid 1
    ```

2. List all connections from all process and threads:

    ```sh
    sudo ./netstat-pid
    ```
3. List all connection to file

    ```sh
    sudo ./netstat-pid > netstat-output.json
    ```
    
## Build


1. Fedora 22

    ```sh
    make build-fedora-32
    ```

2. Ubuntu 22.04

    ```sh
    make build-ubuntu-22.04
    ```
