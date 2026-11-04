CC ?= gcc

CFLAGS ?= -O3 -Wall -Wextra
LDFLAGS ?= -O2

SOURCES = sph_ripemd.c sph_sha2.c sph_sha2big.c

OBJECTS = $(SOURCES:.c=.o)
OUTPUT = libhash.a

all: $(SOURCES) $(OUTPUT)

$(OUTPUT): $(OBJECTS)
	ar rc $@ $(OBJECTS)
	touch ../stratum.cpp

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o *.a
