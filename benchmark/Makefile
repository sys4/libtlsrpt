CC=gcc
DEBUG=-g
CFLAGS += -Wall -I ../library/include ${DEBUG} -O2
CXXFLAGS += ${CFLAGS} -fpermissive
LDFLAGS += -Wall -L. -L ../library/src ${DEBUG}
LDLIBS += ../library/src/libtlsrpt.a

PROGS = bench1
all: ${PROGS}

clean:
	rm *.o *.a ${PROGS}
