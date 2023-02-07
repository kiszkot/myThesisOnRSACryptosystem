LIBS = -lwolfssl

all: server client

server:  
	gcc ./src/server.c -o server $(LIBS)

client: 
	gcc ./src/client.c -o client $(LIBS)

clean:
	rm ./server
	rm ./client