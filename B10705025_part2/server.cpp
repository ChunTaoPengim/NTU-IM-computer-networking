#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <string>
#include <cstring>
#include <pthread.h>
#include <vector>

using namespace std;
struct sockaddr_in client;
void *connection_handler(void *socket_desc);
struct ClientType{
	int money = 10000;
	int login = false;
	int portNum;
	string ipAddr;
	// int public_key;
	string accountName;
	int realport;
};
vector<ClientType> clientList;
int main(int argc, char* argv[])
{
	clientList.clear();
    int socket_desc , new_socket , c , *new_sock;
	struct sockaddr_in server;

    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
	if (socket_desc == -1)
	{
		printf("Could not create socket");
	}
    server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons( atoi(argv[1]) );

    //Bind
	if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
	{
		puts("bind failed");
	}
	puts("bind done");
	
	//Listen
	listen(socket_desc , 3);
	
	//Accept and incoming connection
	puts("Waiting for incoming connections...");
	c = sizeof(struct sockaddr_in);
	
    while( (new_socket = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)) )
	{
		puts("Connection accepted");
		
		//Reply to the client
		
		pthread_t pid;
		
        new_sock = new int[1];
		*new_sock = new_socket;
        char *client_ip = inet_ntoa(client.sin_addr);
        int client_port = ntohs(client.sin_port);
		
		if( pthread_create( &pid , NULL ,  connection_handler , (void*) new_sock) < 0)
		{
			perror("could not create thread");
			return 1;
		}
		
		//Now join the thread , so that we dont terminate before the thread
		//pthread_join( sniffer_thread , NULL);
		puts("Handler assigned");
	}
    if (new_socket<0)
	{
		perror("accept failed");
		return 1;
	}

	return 0;
}
void *connection_handler(void *socket_desc)
{
	//Get the socket descriptor
	int sock = *(int*)socket_desc;
	
	int read_size;
	char *message , client_message[2000];
	puts("Hello");
	string username = "";
	//Send some messages to the client
	while( (read_size = recv(sock , client_message , 2000 , 0)) > 0 )
	{
		//Send the message back to client
		string client_input = client_message;
		if(client_input.substr(0,9) == "REGISTER#")
		{
			bool registered = false;
			 

			for(int i=0;i< clientList.size();i++)
			{
				if(clientList[i].accountName == client_input.substr(9))
				{
					registered = true;
					break;
				}
			}
			if(registered){
				message = "210 FAil\n\0";
				write(sock , message , strlen(message));
				// strcpy(message, "");
			}
			else{
				message = "100 OK\n\0";
				ClientType a;
				a.accountName = client_input.substr(9).c_str() ;
				write(sock , message , strlen(message));
				clientList.push_back(a);
				cout<< clientList.size() << endl;
				memset(client_message, '\0', 2000);
				// strcpy(message, "");
			}
		}
		else{
			char* pch = NULL;
			pch=strchr(client_message,'#');
			if(pch!= NULL)
			{	if(strchr(pch+1,'#')==NULL)
				{
					bool logged = false;
					bool exist = false;
					string temp = client_input.substr(0, client_input.find('#'));
					string client_ip = inet_ntoa(client.sin_addr);
					int client_port = ntohs(client.sin_port);
					int port = atoi(pch+1);
					string reply ="";
					int onlineNumbers = 0;
					for(int i=0; i< clientList.size(); i++)
					{
						if(clientList[i].accountName == temp)
						{
							exist = true;
							clientList[i].login = true;
							clientList[i].ipAddr = client_ip;
							clientList[i].portNum = port;
							clientList[i].realport = client_port;
							username = temp;
							// cout << client_port <<endl;
							reply = (to_string(clientList[i].money)+"\n"+"Public Key\n");
						}
						if(clientList[i].login)
						{
							onlineNumbers ++;
						}
					}

					reply += (to_string(onlineNumbers) + "\n");
					puts("good");
					for(int i=0; i< clientList.size(); i++)
					{
						if(clientList[i].login)
						{
							reply += (clientList[i].accountName+"#"+clientList[i].ipAddr+"#"+to_string(clientList[i].portNum)+"\n");
						}
					}
					if(exist)
					{
						cout<< reply <<endl;
						write(sock , reply.c_str() ,reply.length());
						memset(client_message, '\0', 2000);
					}
					else{
						reply = "220 AUTH_FAil\n\0";
						write(sock , reply.c_str() , reply.length());
						memset(client_message, '\0', 2000);
					}
					
				}
				else{
					string payer = client_input.substr(0, client_input.find('#'));
					string payee = client_input.substr(client_input.find_last_of('#')+1);
					string amount = client_input.substr(client_input.find('#')+1, (client_input.find_last_of('#')-client_input.find('#')-1));
					int transferamount = stoi(amount);
					bool succeed = false;
					if (payee == username)
					{
						for(int i=0; i< clientList.size(); i++)
						{
							if(clientList[i].accountName == payer)
							{
								
								clientList[i].money -= transferamount;
								for (int j=0; i<clientList.size();j++)
								{
									if(clientList[j].accountName == payee)
									{
										clientList[j].money += transferamount;
										succeed = true;
										break;
									}
								}
								break;
							}
							
						}
					}
					if(succeed)
					{
						string reply = "Transfer Ok\n";
						cout<< reply <<endl;
						write(sock , reply.c_str() ,reply.length());
						memset(client_message, '\0', 2000);
					}
					else
					{
						string reply = "Transfer Fail\n";
						cout<< reply <<endl;
						write(sock , reply.c_str() ,reply.length());
						memset(client_message, '\0', 2000);

					}
				}
			

			}
			else 
			{
				if(client_input == "List")
				{
					bool logged = false;
					string client_ip = inet_ntoa(client.sin_addr);
					int client_port = ntohs(client.sin_port);

					string reply = "";
					int onlineNumbers = 0;
					cout << client_port <<endl;
					for(int i=0; i< clientList.size(); i++)
					{
						if(clientList[i].accountName == username)
						{
							if(clientList[i].login)
							{
								logged = true;
								reply = (to_string(clientList[i].money)+"\n"+"Public Key\n");
							}
							
							reply = (to_string(clientList[i].money)+"\n"+"Public Key\n");
						}
						if(clientList[i].login)
						{
							onlineNumbers ++;
						}
					}
					reply += (to_string(onlineNumbers) + "\n");
					
					for(int i=0; i< clientList.size(); i++)
					{
						if(clientList[i].login)
						{
							reply += (clientList[i].accountName+"#"+clientList[i].ipAddr+"#"+to_string(clientList[i].portNum)+"\n");
						}
					}
					if(logged)
					{
						cout<< reply <<endl;
						write(sock , reply.c_str() ,reply.length());
						memset(client_message, '\0', 2000);
					}
					else{
						reply = "220 please log in first\n\0";
						write(sock , reply.c_str() , reply.length());
						memset(client_message, '\0', 2000);
					}
				}
				else if(client_input == "Exit")
				{
					bool logged = false;
					string client_ip = inet_ntoa(client.sin_addr);
					int client_port = ntohs(client.sin_port);

					string reply = "";
					cout << client_port <<endl;
					for(int i=0; i< clientList.size(); i++)
					{
						if(clientList[i].accountName == username)
						{
							clientList[i].ipAddr = "";
							clientList[i].login = false;
							clientList[i].portNum = 0;
							clientList[i].realport =0;	
							logged = true;				
						}
						
					}
					
					if(logged)
					{
						reply = "Bye";
						cout<< reply <<endl;
						write(sock , reply.c_str() ,reply.length());
						memset(client_message, '\0', 2000);
						pthread_exit(0);
					}
					else{

						reply = "please login before exit";
						write(sock , reply.c_str() , reply.length());
						memset(client_message, '\0', 2000);
					}
				}
				
			}
		}

		//write(sock , client_message , strlen(client_message));
	}
	if(read_size == 0)
	{
		puts("Client disconnected");
	}
	else if(read_size == -1)
	{
		perror("recv failed");
	}
		
	//Free the socket pointer

	//Free the socket pointer
	free(socket_desc);
	
	pthread_exit(0);
}