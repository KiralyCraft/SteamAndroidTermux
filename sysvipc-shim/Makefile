CC ?= cc
CFLAGS ?= -O2 -g -fPIC
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Werror

.PHONY: all clean test

all: libsysvsem-shim.so test_sysvsem

libsysvsem-shim.so: sysvsem_shim.c sysvsem.map
	$(CC) $(CFLAGS) -shared -Wl,-z,defs -Wl,--version-script=sysvsem.map -o $@ sysvsem_shim.c

test_sysvsem: test_sysvsem.c
	$(CC) $(CFLAGS) -o $@ test_sysvsem.c

test: all
	LD_PRELOAD=$(CURDIR)/libsysvsem-shim.so ./test_sysvsem

clean:
	rm -f libsysvsem-shim.so test_sysvsem
