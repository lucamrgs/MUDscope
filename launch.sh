#!/bin/bash

function finish() {
        echo "Aborted"
        docker rm -f mudscope
}

trap finish SIGINT

docker rm -f mudscope

echo 'Starting container'
sleep 1

docker run -d --name mudscope -w /mudscope -v "$(pwd):/mudscope" python:3.9-bullseye sh -c "pip3 install --no-cache-dir -r requirements.txt && tail -f /dev/null"
wait

echo 'Setting up container environment'
sleep 3

docker exec mudscope sh -c "apt-get update"
wait
docker exec mudscope sh -c "apt-get install flex -y && apt-get install nfdump -y"
wait
docker exec mudscope sh -c "ldconfig"
wait
docker exec mudscope sh -c "apt-get install build-essential autoconf automake libgtk2.0-dev libglu1-mesa-dev libsdl1.2-dev libglade2-dev gettext zlib1g-dev libosmesa6-dev intltool libagg-dev libasound2-dev libsoundtouch-dev libpcap-dev -y apt-get install bison -y && apt-get install byacc -y"
wait
docker exec mudscope sh -c "cd /.."
wait
docker exec mudscope sh -c "git clone https://github.com/phaag/nfdump.git"
wait
docker exec mudscope sh -c "cd nfdump"
wait
docker exec mudscope sh -c "autoreconf -fi"
wait
docker exec mudscope sh -c "./configure --enable-readpcap --enable-nfpcapd"
wait
docker exec mudscope sh -c "make && make install"
wait
docker exec mudscope sh -c "cd /mudscope"

echo 'MUDscope ready. Access it via $> docker exec -it mudscope /bin/bash'
