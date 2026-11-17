CC=gcc
CXX=g++

CFLAGS= -g -O2 -Wall -Wno-unused-function -Wno-unused-variable -fno-strict-aliasing
SQLCFLAGS= $(shell mysql_config --cflags 2>/dev/null || mariadb_config --cflags 2>/dev/null)
SQLLIBS= $(shell mysql_config --libs 2>/dev/null || mariadb_config --libs 2>/dev/null || echo "-lmysqlclient")

# Direct LBC mining only (no auto-exchange)
CFLAGS += -DNO_EXCHANGE

LDFLAGS= -O2 $(SQLLIBS)

LDLIBS= iniparser/libiniparser.a algos/libalgos.a sha3/libhash.a -lpthread -lm -lstdc++

SOURCES=stratum.cpp db.cpp coind.cpp coind_template.cpp coind_submit.cpp util.cpp list.cpp \
	rpc.cpp job.cpp job_send.cpp job_core.cpp merkle.cpp share.cpp socket.cpp coinbase.cpp \
	client.cpp client_submit.cpp client_core.cpp client_difficulty.cpp \
	user.cpp object.cpp json.cpp base58.cpp

CFLAGS += -DHAVE_CURL
SOURCES += rpc_curl.cpp
LDCURL = $(shell pkg-config --libs libcurl 2>/dev/null || echo "-lcurl")
LDFLAGS += $(LDCURL)

OBJECTS=$(SOURCES:.cpp=.o)
OUTPUT=stratum

CODEDIR1=algos
CODEDIR2=sha3
CODEDIR3=iniparser

.PHONY: projectcode1 projectcode2 projectcode3 clean install

all: projectcode1 projectcode2 projectcode3 $(SOURCES) $(OUTPUT)

projectcode1:
	$(MAKE) -C $(CODEDIR1)

projectcode2:
	$(MAKE) -C $(CODEDIR2)

projectcode3:
	$(MAKE) -C $(CODEDIR3) libiniparser.a

$(SOURCES): stratum.h util.h

$(OUTPUT): $(OBJECTS)
	$(CXX) $(OBJECTS) $(LDLIBS) $(LDFLAGS) -o $@

.cpp.o:
	$(CXX) $(CFLAGS) $(SQLCFLAGS) -c $<

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o $(OUTPUT)
	rm -f algos/*.o algos/*.a
	rm -f sha3/*.o sha3/*.a
	rm -f iniparser/src/*.o iniparser/*.a

install: clean all
	strip $(OUTPUT)
	cp $(OUTPUT) /usr/local/bin/
	cp $(OUTPUT) ../bin/
