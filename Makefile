LIB_DIR=./lib
INCLUDE_DIR=./include
SRC=./src

all:
	gcc -L${LIB_DIR} -I${INCLUDE_DIR} -lndpi -lpcap ${SRC}/ndpiReader.c -fPIC -shared -o src/libndpilua.so /lib/libndpi.so.1 /usr/lib/x86_64-linux-gnu/libpcap.so

clean:
	rm -Rf src/libndpilua.so
