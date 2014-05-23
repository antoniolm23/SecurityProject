CFLAGS 	:= -ggdb -Wall
SECFLAGS	:= -lcrypto
CC := g++
DEBUG ?= 

OBJS := server.o client.o steganography.o util.o key.o

all: security client

security: 		$(OBJS) main.cpp
			$(CC) $(CFLAGS) $(DEBUG) $(SECFLAGS) $^ -o $@ $(DBFLAGS)
			
client:			$(OBJS) cmain.cpp
			$(CC) $(CFLAGS) $(DEBUG) $(SECFLAGS) $^ -o $@ $(DBFLAGS)
			
server.o: 		server.cpp
			g++ -c $(CFLAGS) $(DEBUG) server.cpp
			
client.o:		client.cpp
			g++ -c $(CFLAGS) $(DEBUG) client.cpp
	
steganography.o:	steganography.cpp
			g++ -c $(CFLAGS) $(DEBUG) steganography.cpp
			
key.o:			key.cpp
			g++ -c $(CFLAGS) $(DEBUG) $(SECFLAGS) key.cpp
			
util.o: 		util.cpp
			g++ -c $(CFLAGS) $(DEBUG) util.cpp
			
clean: 			
			rm -f *.o
