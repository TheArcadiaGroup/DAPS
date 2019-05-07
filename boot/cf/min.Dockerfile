
ARG SRC_PATH=ubuntu
ARG OS_VERSION=16.04

FROM ${SRC_PATH}:${OS_VERSION}
ENV SRC_IMG=${SRC_PATH}:${OS_VERSION}

#INSTALL libs to run DAPS
RUN apt-get update && \
    apt-get install software-properties-common -y --fix-missing && \
    add-apt-repository ppa:bitcoin/bitcoin -y && \
    apt-get update && \
    apt-get install libminiupnpc-dev libevent-dev libzmq3-dev libboost-all-dev libdb4.8++-dev libdb4.8-dev libssl1.0-dev nano -y --fix-missing && \
#
    mkdir -p /usr/bin && \
    mkdir -p ~/.dapscoin/

#COPY binaries
COPY dapscoind /usr/bin/dapscoind
COPY dapscoin-cli /usr/bin/dapscoin-cli

EXPOSE 53575 53573 53572

CMD /bin/bash -c "trap: TERM INT; sleep infinity & wait"
