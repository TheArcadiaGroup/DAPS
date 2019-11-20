ARG SRC_PATH=ubuntu
ARG OS_VERSION=18.04

FROM ${SRC_PATH}:${OS_VERSION}
ENV SRC_IMG=${SRC_PATH}:${OS_VERSION}

#INSTALL COMMON ESSENTIAL
RUN apt-get update && \
    apt-get install build-essential libtool autotools-dev automake pkg-config bsdmainutils curl wget nsis libevent-dev python-setuptools patch zip -y --fix-missing

#INSTALL POA MINER DEPENDENCIES
RUN apt-get install libcurl4-openssl-dev libjansson-dev -y --fix-missing

#CLEANUP UNUSED PACKAGES
RUN apt-get autoremove -y

CMD /bin/bash -c "trap: TERM INT; sleep infinity & wait"