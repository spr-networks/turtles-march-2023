FROM ubuntu:22.04

RUN apt-get update
RUN apt-get -y install iproute2 wireless-tools iw nano tcpdump inetutils-ping netcat
RUN apt-get -y install wpasupplicant
RUN apt-get -y install openssh-server
RUN apt-get -y install python3 python3-pip
RUN apt-get -y install net-tools
RUN pip install scapy

COPY turtleap /turtleap/
COPY go.sh /
# Need to wait for orchestrator to run go.sh
ENTRYPOINT ["/bin/bash"]
