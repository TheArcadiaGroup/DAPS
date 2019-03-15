DEPS="./win64_deps"
autoreconf -fi -I${DEPS}/share/aclocal
./configure --host=x86_64-w64-mingw32 \
CFLAGS="-DWIN32 -DCURL_STATICLIB -O3 -std=c99 -I${DEPS}/include -I./include -DPTW32_STATIC_LIB" \
--with-libcurl=${DEPS} LDFLAGS="-static -L${DEPS}/lib -L./lib"

make
