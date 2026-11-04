CXX=g++

CFLAGS=-c -O2 -Wall
LDFLAGS=-O2
LDLIBS=

SOURCES=blocknotify.cpp
OBJECTS=$(SOURCES:.cpp=.o)
OUTPUT=blocknotify

.PHONY: all install clean

all: $(SOURCES) $(OUTPUT)

$(OUTPUT): $(OBJECTS)
	$(CXX) $(OBJECTS) $(LDLIBS) $(LDFLAGS) -o $@

.cpp.o:
	$(CXX) $(CFLAGS) $< -o $@

install: all
	strip $(OUTPUT)
	mv $(OUTPUT) ../bin/

clean:
	rm -f *.o $(OUTPUT)
