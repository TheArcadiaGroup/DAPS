ARG SRC_PATH=r.cfcr.io/hysmagus
ARG SRC_NAME=build_deps
ARG SRC_TAG=develop

FROM ${SRC_PATH}/${SRC_NAME}:${SRC_TAG}
ENV SRC_IMG=${SRC_PATH}/${SRC_NAME}:${SRC_TAG}

ARG BUILD_TARGET=linux
ENV BUILD_TARGET=${BUILD_TARGET}

ARG DESTDIR=/daps/bin/
ENV DESTDIR=$DESTDIR

#COPY source
COPY . /DAPS/

# instructions from @zues16 for compiling with license using chilkat
RUN apt-get update && apt-get install libcpprest-dev wget cmake -y --fix-missing
RUN cd /DAPS/depends/x86_64-w64-mingw32/include/ && \
    mkdir -p chilkat-9.5.0 && \
    cp ../../chilkat/include/* chilkat-9.5.0 && \
    cd .. && \
    cp ../chilkat/lib/* ./
#           wget "https://chilkatdownload.com/9.5.0.76/chilkat-9.5.0-x86_64-linux-gcc.tar.gz" && \
#           tar -xvf chilkat-9.5.0-x86_64-linux-gcc.tar.gz && \
#       END chilkat

RUN cd /DAPS/ && mkdir -p /BUILD/ && \
#     
    if [ "$BUILD_TARGET" = "windows" ]; \
      then echo "Compiling for win64" && \
        ./autogen.sh && \
        CONFIG_SITE=$PWD/depends/x86_64-w64-mingw32/share/config.site ./configure --prefix=/ && \
        make HOST=x86_64-w64-mingw32 && \
        make install HOST=x86_64-w64-mingw32 DESTDIR=/BUILD/; \
#
    elif [ "$BUILD_TARGET" = "linux" ]; \
       then echo "Compiling for linux" && \
         ./autogen.sh && ./configure && \
         make && \
         make install DESTDIR=/BUILD/; \
#
    elif [ "$BUILD_TARGET" = "mac" ]; \
       then echo "Compiling for mac" && \
         ./autogen.sh --with-gui=yes && CONFIG_SITE=$PWD/depends/x86_64-apple-darwin11/share/config.site ./configure --prefix=/ && \
         make HOST="x86_64-apple-darwin11" && \
         make install HOST="x86_64-apple-darwin11" DESTDIR=/BUILD/; \
#
    else echo "Build target not recognized."; \
      exit 127; \
#
    fi

RUN cd /BUILD/ && \
    mkdir -p $DESTDIR && \
    #files only
    find ./ -type f | \
    #flatten
    tar cvf - --transform 's/.*\///g' --files-from=/dev/stdin | \
    #compress
    xz -9 - > $DESTDIR$BUILD_TARGET.tar.xz

CMD /bin/bash -c "trap: TERM INT; sleep infinity & wait"