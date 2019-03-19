ARG SRC_PATH=r.cfcr.io/hysmagus
ARG SRC_NAME=build_deps
ARG SRC_TAG=public-beta

FROM ${SRC_PATH}/${SRC_NAME}:${SRC_TAG}
ENV SRC_IMG=${SRC_PATH}/${SRC_NAME}:${SRC_TAG}

ARG BUILD_TARGET=linux
ENV BUILD_TARGET=${BUILD_TARGET}

ARG DESTDIR=/daps/bin/
ENV DESTDIR=$DESTDIR

#COPY source
COPY . /DAPS/

RUN apt-get update && apt-get install libcpprest-dev wget cmake -y --fix-missing
RUN cd /DAPS/ && mkdir -p /BUILD/ && \
#
    if [ "$BUILD_TARGET" = "windowsx64" ]; \
      then echo "Compiling for win64" && \
        mkdir -p depends/x86_64-w64-mingw32/include/chilkat-9.5.0 && \
        cp depends/chilkat/include/* depends/x86_64-w64-mingw32/include/chilkat-9.5.0 && \
        mkdir -p depends/x86_64-w64-mingw32/lib && \
        cp depends/chilkat/lib/* depends/x86_64-w64-mingw32/lib && \
        ./autogen.sh && \
        CONFIG_SITE=$PWD/depends/x86_64-w64-mingw32/share/config.site ./configure --prefix=/ && \
        make HOST=x86_64-w64-mingw32 -j2 && \
        make install HOST=x86_64-w64-mingw32 DESTDIR=/BUILD/; \
#
    elif [ "$BUILD_TARGET" = "windowsx86" ]; \
      then echo "Compiling for win86" && \
        mkdir -p depends/i686-w64-mingw32/include/chilkat-9.5.0 && \
        cp depends/chilkat/x86/include/* depends/i686-w64-mingw32/include/chilkat-9.5.0 && \
        mkdir -p depends/i686-w64-mingw32/lib && \
        cp depends/chilkat/x86/lib/* depends/i686-w64-mingw32/lib && \
        ./autogen.sh && \
        CONFIG_SITE=$PWD/depends/i686-w64-mingw32/share/config.site ./configure --prefix=/ && \
        make HOST=i686-w64-mingw32 -j2 && \
        make install HOST=i686-w64-mingw32 DESTDIR=/BUILD/; \
#
    elif [ "$BUILD_TARGET" = "linux" ]; \
       then echo "Compiling for linux" && \
        ./autogen.sh && \
        CONFIG_SITE=$PWD/depends/x86_64-pc-linux-gnu/share/config.site ./configure --prefix=/ && \
        make HOST=x86_64-pc-linux-gnu -j2 && \
        make install DESTDIR=/BUILD/; \
#
    elif [ "$BUILD_TARGET" = "mac" ]; \
       then echo "Compiling for mac" && \
        ./autogen.sh --with-gui=yes && \
        CONFIG_SITE=$PWD/depends/x86_64-apple-darwin11/share/config.site ./configure --prefix=/ && \
        make HOST="x86_64-apple-darwin11" -j2 && \
        make deploy && \
        make install HOST="x86_64-apple-darwin11" DESTDIR=/BUILD/ && \
        cp Dapscoin-Core.dmg /BUILD/bin/; \
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