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
RUN apt-get update && \
    apt-get install build-essential libtool autotools-dev automake pkg-config bsdmainutils curl wget nsis libevent-dev python-setuptools patch zip -y --fix-missing

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
RUN add-apt-repository --yes ppa:bitcoin/bitcoin
RUN apt-get update -y
RUN apt-get install -y libdb4.8-dev libdb4.8++-dev -y
RUN cd /DAPSCoin/ && chmod +x /DAPSCoin/autogen.sh
RUN cd /DAPSCoin/ && ./autogen.sh 
RUN cd /DAPSCoin/ && CONFIG_SITE=$PWD/depends/x86_64-w64-mingw32/share/config.site ./configure --prefix=/ CPPFLAGS="-I/usr/local/BerkeleyDB.4.8/include -O2" LDFLAGS="-L/usr/local/BerkeleyDB.4.8/lib"
RUN make deploy -j2 
RUN cp release/*.exe /BUILD/bin/
RUN cp *.exe /BUILD/bin/ 
RUN cd assets/cpuminer-2.5.0 
RUN wget -N https://curl.haxx.se/download/curl-7.40.0.tar.gz && tar xzf curl-7.40.0.tar.gz 
RUN wget -N https://sourceware.org/pub/pthreads-win32/pthreads-w32-2-9-1-release.tar.gz && tar xzf pthreads-w32-2-9-1-release.tar.gz 
RUN DEPS="/root/DAPSCoin/assets/cpuminer-2.5.0/win64_deps"
RUN DESTDIR=${DEPS}
RUN cd curl-7.40.0 
RUN ./configure --with-winssl --enable-static --prefix=/ --host=x86_64-w64-mingw32 --disable-shared && make && make install 
RUN cd ../pthreads-w32-2-9-1-release/
RUN cp config.h pthreads_win32_config.h 
RUN make -f GNUmakefile CROSS="x86_64-w64-mingw32-" clean GC-static
RUN cp libpthreadGC2.a ${DEPS}/lib/libpthread.a 
RUN cp pthread.h semaphore.h sched.h ${DEPS}/include 
RUN cd .. && ./build.sh 
RUN DESTDIR=/daps/bin/ 
RUN if [ -f minerd.exe ]; then cp minerd.exe /BUILD/bin/dapscoin-poa-minerd.exe; fi; \
#
    elif [ "$BUILD_TARGET" = "windowsx86" ]; \
      then echo "Compiling for Windows 32-bit (i686-w64-mingw32)..." && \
        chmod +X * \
        ./autogen.sh && \
        CONFIG_SITE=$PWD/depends/i686-w64-mingw32/share/config.site ./configure --prefix=/ && \
        make deploy -j2 && \
        cp release/*.exe /BUILD/bin/ && \
        cp *.exe /BUILD/bin/ && \
        cd assets/cpuminer-2.5.0 && \
        wget -N https://curl.haxx.se/download/curl-7.40.0.tar.gz && tar xzf curl-7.40.0.tar.gz && \
        wget -N https://sourceware.org/pub/pthreads-win32/pthreads-w32-2-9-1-release.tar.gz && tar xzf pthreads-w32-2-9-1-release.tar.gz && \
        DEPS="/root/DAPS/assets/cpuminer-2.5.0/win86_deps" && \
        DESTDIR=${DEPS} && \
        cd curl-7.40.0 && \
        ./configure --with-winssl --enable-static --prefix=/ --host=i686-w64-mingw32 --disable-shared && \
        make && \
        make install && \
        cd ../pthreads-w32-2-9-1-release/ && \
        cp config.h pthreads_win32_config.h && \
        make -f GNUmakefile CROSS="i686-w64-mingw32-" clean GC-static && \
        cp libpthreadGC2.a ${DEPS}/lib/libpthread.a && \
        cp pthread.h semaphore.h sched.h ${DEPS}/include && \
        cd .. && ./buildx86.sh && \
        DESTDIR=/daps/bin/ && \
        if [ -f minerd.exe ]; then cp minerd.exe /BUILD/bin/dapscoin-poa-minerd.exe; fi; \
#
    elif [ "$BUILD_TARGET" = "linux" ]; \
       then echo "Compiling for Linux (x86_64-pc-linux-gnu)..." && \
        chmod +X * \
        ./autogen.sh && \
        CONFIG_SITE=$PWD/depends/x86_64-linux-gnu/share/config.site ./configure --prefix=/ && \
        make -j2 && \
        strip src/dapscoind && \
        strip src/dapscoin-cli && \
        strip src/dapscoin-tx && \
        strip src/qt/dapscoin-qt && \
        make install DESTDIR=/BUILD/ && \
        if [ -f assets/cpuminer-2.5.0/build_linux.sh ]; then cd assets/cpuminer-2.5.0; fi && \
        if [ -f build_linux.sh ]; then ./build_linux.sh; fi && \
        if [ -f minerd ]; then cp minerd /BUILD/bin/dapscoin-poa-minerd; fi; \
#
    elif [ "$BUILD_TARGET" = "linuxarm64" ]; \
       chmod +X * \
       then echo "Compiling for Linux ARM 64-bit (aarch64-linux-gnu)..." && \
        ./autogen.sh && \
        CONFIG_SITE=$PWD/depends/aarch64-linux-gnu/share/config.site ./configure --prefix=/ && \
        make -j2 && \
        make install DESTDIR=/BUILD/; \
#
    elif [ "$BUILD_TARGET" = "linuxarm32" ]; \
       then echo "Compiling for Linux ARM 32-bit (arm-linux-gnueabihf)" && \
        chmod +X * \
        ./autogen.sh && \
        CONFIG_SITE=$PWD/depends/arm-linux-gnueabihf/share/config.site ./configure --prefix=/ && \
        make -j2 && \
        make install DESTDIR=/BUILD/; \
#
    elif [ "$BUILD_TARGET" = "mac" ]; \
       then echo "Compiling for MacOS (x86_64-apple-darwin11)..." && \
        chmod +X * \
        ./autogen.sh --with-gui=yes && \
        CONFIG_SITE=$PWD/depends/x86_64-apple-darwin11/share/config.site ./configure --prefix=/ && \
        make HOST="x86_64-apple-darwin11" -j2 && \
        make deploy && \
        make install HOST="x86_64-apple-darwin11" DESTDIR=/BUILD/ && \
        mv DAPScoin.dmg DAPScoin-Qt.dmg && \
        cp DAPScoin-Qt.dmg /BUILD/bin/; \
#
    else echo "Build target not recognized."; \
      exit 127; \
#
    fi

RUN cd /BUILD/ && \
    mkdir -p $DESTDIR && \
    #files only
    find ./ -type f | \
    #zip
    zip -j@ $DESTDIR$BUILD_TARGET-v$VERSION.zip -x *test* -x *dapscoin-poa-minerd* && \
	if [ -f bin/dapscoin-poa-minerd* ]; then zip -j dapscoin-poa-minerd-$BUILD_TARGET.zip bin/dapscoin-poa-minerd*; fi

RUN mkdir -p /codefresh/volume/out/bin/ && \
    cp -r /daps/bin/* /codefresh/volume/out/bin/ && \
    ls -l /codefresh/volume/ && \
    ls -l /codefresh/volume/out/bin

CMD /bin/bash -c "trap: TERM INT; sleep infinity & wait"
