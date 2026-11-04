CC ?= gcc

CFLAGS ?= -O2 -I.. -Wall -Wextra
LDFLAGS ?= -O2

SOURCES = lbry.c sha256.c

OBJECTS = $(SOURCES:.c=.o)
OUTPUT = libalgos.a

all: $(SOURCES) $(OUTPUT)

$(OUTPUT): $(OBJECTS)
	ar rc $@ $(OBJECTS)
	touch ../stratum.cpp

.c.o:
	$(CC) $(CFLAGS) -std=gnu99 -c $< -o $@

clean:
	rm -f *.o *.a
