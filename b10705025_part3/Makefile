all:client server
client:client.cpp
	g++ -o client client.cpp -lssl -lcrypto -pthread
server:server.cpp
	g++ -o server server.cpp -lssl -lcrypto -pthread
clean:all
	rm all