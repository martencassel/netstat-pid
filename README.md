# Netstat-pid 

Netstat-pid display 'netstat' connectivity information for processes and threads on a host.

* Display network connections from all processes including threads on a host (default).
* Display both hostname and container name if available, in the UTS namespace.
* Displays network connections for a specific pid.
* Write connectivity information as json to standard out.

## How It Works

1. Traverses the entire process tree and each thread 
2. Reads connection information from proc files tcp and tcp6, per process and thread.
3. Outputs the connection information as JSON to stdout.

## Usage

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
