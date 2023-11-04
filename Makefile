default:
	CGO_ENABLED=0 go build

build-ubuntu-22.04:
	docker build -t netstat-pid:ubuntu-22.04 -f Dockerfile.ubuntu-22.04 . 
	docker container rm -f builder||true
	docker run --name=builder -d netstat-pid:ubuntu-22.04 sleep infinity 
	docker cp builder:/netstat-pid netstat-pid-ubuntu-22
	mv netstat-pid-ubuntu-22 ./dist/

build-fedora-32:
	docker build -t netstat-pid:fedora-32 -f Dockerfile.fedora-32 . 
	docker container rm -f builder||true
	docker run --name=builder -d netstat-pid:fedora-32 sleep infinity 
	docker cp builder:/netstat-pid netstat-pid-fedora-32
	mv netstat-pid-fedora-32 ./dist/

build-all-docker:
	make build-ubuntu-22.04
	make build-fedora-32

