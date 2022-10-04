# Start with ubuntu image
FROM ubuntu:22.04

# Set working directory
WORKDIR /mudscope

# Install dependencies
RUN apt-get update && \
    apt-get upgrade -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install \
    git default-jre maven tcpdump wireshark build-essential libpcap-dev \
    libtool pkg-config flex libbz2-dev autotools-dev byacc python3-pip -y

# Install mudgee
RUN git clone https://github.com/ayyoob/mudgee.git && \
    cd mudgee && \
    mvn clean install && \
    cd ..

# Install nfpcapd
RUN git clone https://github.com/phaag/nfdump.git && \
    cd nfdump && \
    git checkout v1.6.24 && \
    ./autogen.sh && \
    ./configure --enable-nfpcapd && \
    make && \
    make install && \
    cp ./bin/.libs/libnfdump-1.6.24.so /usr/lib/ && \
    cd /mudscope

# Install MUDscope
COPY requirements.txt .
RUN pip3 install -r requirements.txt
COPY . /mudscope/
RUN pip3 install -e .

# Copy examples
COPY examples/ /mudscope/examples/
