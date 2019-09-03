ARG SRC_PATH=ubuntu
ARG OS_VERSION=16.04

FROM ${SRC_PATH}:${OS_VERSION}
ENV SRC_IMG=${SRC_PATH}:${OS_VERSION}

#INSTALL COMMON ESSENTIAL
RUN apt-get update && \
    apt-get install autotools-dev build-essential autoconf make automake openssl wget nsis -y --fix-missing && \
    apt-get install gnupg software-properties-common debconf dialog apt-utils gcc-5 bsdmainutils curl git -y --fix-missing

#INSTALL BC
RUN add-apt-repository ppa:bitcoin/bitcoin -y && \
    apt-get update

#INSTALL LIBS
RUN apt-get install libssl-dev libboost-dev libtool  pkg-config libunwind-dev libreoffice -y --fix-missing && \
    apt-get install libminiupnpc-dev miniupnpc libdb4.8++-dev libdb4.8-dev libqrencode-dev libevent-dev -y --fix-missing && \
    apt-get install libqt5gui5 libqt5core5a libqt5dbus5 qt5-default qttools5-dev qttools5-dev-tools -y --fix-missing && \
    apt-get install libprotobuf-dev libboost-all-dev protobuf-compiler -y --fix-missing && \
    apt-get install libqrencode-dev -y --fix-missing && \
    apt-get install libfontconfig1 mesa-common-dev libglu1-mesa-dev -y --fix-missing
    apt-get install libunivalue-dev -y --fix-missing

#USE G++5
RUN apt-get install g++-5 libcurl4-openssl-dev libjansson-dev -y --fix-missing && \
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-5 1 && \
#
    apt-get update

#USE cpprest-dev
RUN apt-get install libboost-atomic-dev libboost-thread-dev libboost-system-dev libboost-date-time-dev -y --fix-missing && \
    apt-get install libboost-regex-dev libboost-filesystem-dev libboost-random-dev libboost-chrono-dev -y --fix-missing && \
    apt-get install libboost-serialization-dev libwebsocketpp-dev libssl1.0-dev ninja-build cmake -y --fix-missing && \
    git clone https://github.com/Microsoft/cpprestsdk.git casablanca && \
    cd casablanca && \
    mkdir build.debug && \
    cd build.debug && \
    cmake -G Ninja .. -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=0 && \
    ninja && \
    ninja install
	
#Cleanup packages
RUN apt-get autoremove -y

CMD /bin/bash -c "trap: TERM INT; sleep infinity & wait"
