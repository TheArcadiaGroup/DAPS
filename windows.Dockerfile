FROM ubuntu:18.04
ENV SRC_IMG=ubuntu:18.04

ARG BUILD_TARGET=linux
ENV BUILD_TARGET=windowsx64

ARG DESTDIR=/daps/bin/
ENV DESTDIR=$DESTDIR

ARG VERSION=UNTAGGED
ENV VERSION=$VERSION

#COPY source
RUN apt-get update


RUN apt-get install git autoconf -y
RUN git clone https://github.com/DAPSCoin/DAPSCoin.git
RUN apt-get update

RUN apt-get autoremove -y
#INSTALL COMMON ESSENTIAL
RUN apt-get update -y
##RUN apt-get install curl -y
RUN apt-get install g++-mingw-w64-x86-64 -y
RUN apt-get install curl librsvg2-bin libtiff-tools bsdmainutils cmake imagemagick libcap-dev libz-dev libbz2-dev python3-setuptools -y
RUN apt-get install libzmq3-dev build-essential libtool autotools-dev automake pkg-config wget nsis libevent-dev python-setuptools patch zip -y --fix-missing
RUN apt-get install libssl-dev libqt5gui5 libboost-all-dev libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools libprotobuf-dev protobuf-compiler libqrencode-dev -y
#INSTALL POA MINER DEPENDENCIES
RUN apt-get install libcurl4-openssl-dev libjansson-dev -y --fix-missing

#CLEANUP UNUSED PACKAGES
RUN apt-get autoremove -y

RUN cd /DAPSCoin/ && mkdir -p /BUILD/bin/ 
# RUN wget http://download.oracle.com/berkeley-db/db-4.8.30.NC.tar.gz
# RUN tar -xzvf db-4.8.30.NC.tar.gz
# RUN cd db-4.8.30.NC/build_unix && make && make install
# RUN export BDB_INCLUDE_PATH="/usr/local/BerkeleyDB.4.8/include"
# RUN export BDB_LIB_PATH="/usr/local/BerkeleyDB.4.8/lib"
# RUN ln -s /usr/local/BerkeleyDB.4.8/lib/libdb-4.8.so /usr/lib/libdb-4.8.so
# RUN ln -s /usr/local/BerkeleyDB.4.8/lib/libdb_cxx-4.8.so /usr/lib/libdb_cxx-4.8.so
RUN cp /etc/apt/sources.list /etc/apt/sources.list.bak
RUN wget https://launchpad.net/~bitcoin-abc/+archive/ubuntu/ppa/+files/libdb4.8_4.8.30-xenial4_amd64.deb
RUN dpkg -i libdb4.8_4.8.30-xenial4_amd64.deb
RUN wget https://launchpad.net/~bitcoin-abc/+archive/ubuntu/ppa/+files/libdb4.8-dev_4.8.30-xenial4_amd64.deb
RUN dpkg -i libdb4.8-dev_4.8.30-xenial4_amd64.deb
RUN wget https://launchpad.net/~bitcoin-abc/+archive/ubuntu/ppa/+files/libdb4.8++_4.8.30-xenial4_amd64.deb
RUN dpkg -i libdb4.8++_4.8.30-xenial4_amd64.deb
RUN wget https://launchpad.net/~bitcoin-abc/+archive/ubuntu/ppa/+files/libdb4.8++-dev_4.8.30-xenial4_amd64.deb
RUN dpkg -i libdb4.8++-dev_4.8.30-xenial4_amd64.deb
RUN apt-get update -y
RUN cd /DAPSCoin/depends/; chmod +x /DAPSCoin/depends/*; make HOST=x86_64-w64-mingw32
RUN cd /DAPSCoin/; chmod +x /DAPSCoin/autogen.sh; ./autogen.sh
RUN chmod 777 /DAPSCoin/share/genbuild.sh
RUN chmod 777 /DAPSCoin/src/leveldb/*
RUN cd /DAPSCoin/; CONFIG_SITE=$PWD/depends/x86_64-w64-mingw32/share/config.site ./configure --with-libressl --prefix=/; make  
RUN cp /DAPSCoin/src/*.exe /DAPSCoin/BUILD/bin/
RUN cp *.exe /BUILD/bin/ 
RUN cd assets/cpuminer-2.5.0 
RUN wget -N https://curl.haxx.se/download/curl-7.40.0.tar.gz && tar xzf curl-7.40.0.tar.gz 
RUN wget -N https://sourceware.org/pub/pthreads-win32/pthreads-w32-2-9-1-release.tar.gz && tar xzf pthreads-w32-2-9-1-release.tar.gz 
RUN DEPS="/root/DAPSCoin/assets/cpuminer-2.5.0/win64_deps"
RUN DESTDIR=${DEPS}
RUN cd curl-7.40.0 
RUN chmod +x ./configure; ./configure --with-winssl  --enable-static --prefix=/ --host=x86_64-w64-mingw32 --disable-shared; make; make install 
RUN cd ../pthreads-w32-2-9-1-release/
RUN cp config.h pthreads_win32_config.h 
RUN make -f GNUmakefile CROSS="x86_64-w64-mingw32-" clean GC-static
RUN cp libpthreadGC2.a ${DEPS}/lib/libpthread.a 
RUN cp pthread.h semaphore.h sched.h ${DEPS}/include 
RUN cd .. && ./build.sh 

CMD /bin/bash -c "trap: TERM INT; sleep infinity & wait"
