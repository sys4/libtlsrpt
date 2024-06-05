CC=gcc
DEBUG=-g
CFLAGS += -Wall -I ../include -O2 ${DEBUG}
LDFLAGS += -Wall -L. ${DEBUG}
LDLIBS += libtlsrpt.a

TARGETLIBS=libtlsrpt.a
TARGETBINS=demo
TARGETS=${TARGETLIBS} ${TARGETBINS}

all: ${TARGETS}

${TARGETBINS} : ${TARGETLIBS}

clean:
	rm *.o create-json-escape-initializer-list json-escape-initializer-list.c ${TARGETS}

libtlsrpt.a : libtlsrpt.o json-escape-initializer-list.o
	ar -rcs $@ $^

demo : demo.o libtlsrpt.a

demo.o : ../include/tlsrpt.h
libtlsrpt.o : ../include/tlsrpt.h


json-escape-initializer-list.c : create-json-escape-initializer-list
	./create-json-escape-initializer-list > json-escape-initializer-list.c

create-json-escape-initializer-list : LDLIBS =


