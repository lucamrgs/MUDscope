FROM python:3.9-bullseye

WORKDIR /mudscope

COPY requirements.txt requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install flex -y && apt-get install default-jdk -y && apt-get install maven -y && apt-get install nfdump -y && apt-get install bison -y && apt-get install byacc -y
RUN apt-get install build-essential autoconf automake libgtk2.0-dev libglu1-mesa-dev libsdl1.2-dev libglade2-dev gettext zlib1g-dev libosmesa6-dev intltool libagg-dev libasound2-dev libsoundtouch-dev libpcap-dev -y

COPY . .
RUN if [ -d /outputs/ut-tplink-demo ]; then rm -Rf /outputs/ut-tplink-demo; fi && if [ -d /outputs/tue-tplink-demo ]; then rm -Rf /outputs/tue-tplink-demo; fi
RUN cd .. && git clone https://github.com/phaag/nfdump.git && cd nfdump && autoreconf -fi && ./configure --enable-readpcap --enable-nfpcapd && make && make install
RUN cd ../mudscope/mudgee && mvn clean install && cd ..
RUN ldconfig

CMD ["tail", "-f", "/dev/null"]