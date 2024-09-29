#    Copyright (C) 2024 sys4 AG
#    Author Boris Lohner bl@sys4.de
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Lesser General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public
#    License along with this program.
#    If not, see <http://www.gnu.org/licenses/>.

CC=gcc
INSTALL=install

DEBUG=-g
CFLAGS += -Wall -I . -fPIC -O2 ${DEBUG}
LDFLAGS += -Wall -L. ${DEBUG}
LDLIBS += libtlsrpt.a

TARGETLIBS=libtlsrpt.a libtlsrpt.so
TARGETBINS=demo
TARGETS=${TARGETLIBS} ${TARGETBINS}

all: ${TARGETS}

${TARGETBINS} : ${TARGETLIBS}

clean:
	rm *.o create-json-escape-initializer-list json-escape-initializer-list.c ${TARGETS}

libtlsrpt.a : libtlsrpt.o json-escape-initializer-list.o
	ar -rcs $@ $^

libtlsrpt.so : libtlsrpt.o json-escape-initializer-list.o
	${CC} -shared -o $@ $^

demo : demo.o libtlsrpt.a

demo.o : tlsrpt.h
libtlsrpt.o : tlsrpt.h


json-escape-initializer-list.c : create-json-escape-initializer-list
	./create-json-escape-initializer-list > json-escape-initializer-list.c

create-json-escape-initializer-list : LDLIBS =


install: ${TARGETLIBS} 
	${INSTALL} -D -t ${DESTDIR}${PREFIX}/lib ${TARGETLIBS} 
	${INSTALL} -D -t ${DESTDIR}${PREFIX}/include tlsrpt.h 
