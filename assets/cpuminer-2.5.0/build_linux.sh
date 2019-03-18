./autogen.sh
./configure CFLAGS="-O3"
make -e LIBCURL="$(/tmp/curl/bin/curl-config --static-libs) -ldl"