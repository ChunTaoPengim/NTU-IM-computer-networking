#include<stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/select.h>
#include<sys/socket.h>
#include<arpa/inet.h>	//inet_addr

int socket_desc;

void* receive_thread(void* socket_fd)
{
    int s_fd = *((int*)socket_fd);
	struct sockaddr_in address;
	char buffer[2000] = { 0 };
	int addrlen = sizeof(address);
	int client_socket;
    while (1) {
		
        client_socket = accept(s_fd, (struct sockaddr*)&address,
                             (socklen_t*)&addrlen);
                        
		int tmp_byte_read = recv(client_socket, buffer, sizeof(buffer), 0);		
        send(socket_desc, buffer, strlen(buffer), 0);
		// if( recv(socket_desc, buffer , 2000 , 0) < 0)
		// {
		// 	puts("recv failed");
		// }
		// puts(buffer);
		puts("awaiting transabtion");
		sleep(3);
		if( send(socket_desc , "List" , 4 , 0) < 0)
		{
			puts("Send failed");
		}

		if( recv(socket_desc, buffer , 2000 , 0) < 0)
		{
			puts("recv failed");
		}
		// puts(buffer);
		memset(buffer, '\0', sizeof(buffer));
                    
    }
    pthread_exit(0);
}

int main(int argc , char *argv[])
{
	
	struct sockaddr_in server;
	int clientport = 0;
	char* username = NULL;
	
	char server_reply[2000];
	char client_message[2000];
	//Create socket
	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
	if (socket_desc == -1)
	{
		printf("Could not create socket");
	}
	// printf(argc);
    char* A = argv[1];
    char* port = argv[2];
	server.sin_addr.s_addr = inet_addr(A);
	server.sin_family = AF_INET;

    int portnumber = atoi(port);
	server.sin_port = htons( portnumber );

	
	//Connect to remote server
	if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0)
	{
		puts("connect error");
		return 1;
	}
	puts("Connected");

	

	int client_socket_desc;

	struct sockaddr_in client_server, client;
		
	//Create socket
	
		
	
		
	
	

	while(1){
		

		printf("%s",">");
		
		

		char user_input[100];
		scanf("%s", user_input);
		

		char* pch = NULL;
		pch=strchr(user_input,'#');

		if(pch!= NULL)
		{
			
			int pos = (int)(pch - user_input);
			char temp[] = "REGISTER";
			if((pos == 8) && (strncmp(user_input, temp, 8) == 0))
			{
				
				if( send(socket_desc , user_input , strlen(user_input) , 0) < 0)
				{
					puts("Send failed");
					return 1;
				}
				puts("Start register\n");

				if( recv(socket_desc, server_reply , 2000 , 0) < 0)
				{
					puts("recv failed");
				}
				puts(server_reply);
				memset(server_reply, '\0', sizeof(server_reply));
				
			}
			else if(pos == 0)
			{
				puts("don't start with #");
			}
			else if(strchr(pch+1,'#')==NULL && username == NULL)
			{

				clientport = atoi(pch+1);

				if(clientport <= 65535 && clientport >=1024)
				{

					if( send(socket_desc , user_input , strlen(user_input) , 0) < 0)
					{
						puts("Send failed");
						return 1;
					}
					puts("Start login\n");

					if( recv(socket_desc, server_reply , 2000 , 0) < 0)
					{
						puts("recv failed");
					}
					
					puts(server_reply);
					char* t = strchr(server_reply,'#');
					if( t !=NULL)
					{
						
						client_socket_desc = socket(AF_INET , SOCK_STREAM , 0);
						if (client_socket_desc == -1)
						{
							printf("Could not create client socket");
						}
						
						puts("accepted by server");
						int Length = (int)(pch - user_input);
						username = (char*)malloc(50);
						strncpy(username, user_input, Length);
						username[Length] = '\0';
						puts(username);
						memset(server_reply, '\0', sizeof(server_reply));
						
						client_server.sin_family = AF_INET;
						client_server.sin_addr.s_addr = INADDR_ANY;
						client_server.sin_port = htons( clientport );
							
						//Bind
						if( bind(client_socket_desc,(struct sockaddr *)&client_server , sizeof(client_server)) < 0)
						{
							puts("bind failed\n");
							if( send(socket_desc , "Exit" , 4 , 0) < 0)
							{
								puts("Send failed");
								return 1;
							}
							puts("Start exit");
							sleep(1);
							puts("exit send");

							// if( recv(socket_desc, server_reply , 2000 , 0) < 0)
							// {
							// 	puts("recv failed");
							// }
							// puts(server_reply);
							// memset(server_reply, '\0', sizeof(server_reply));
							username = NULL;
							close(client_socket_desc);
							puts("can't use this port, try another one");
							return 0;

							
						}
						else{
							listen(client_socket_desc,5);

							pthread_t tid;
							// Creating thread to keep receiving message in real time
							pthread_create(&tid, NULL, &receive_thread, &client_socket_desc);
						}
						
						
					}
					else{
						puts("log in failed");
					}
				}
				else{
					puts("client port must be in 1024 to 65535");
				}
				
				

			}
			else if(pch == user_input)
			{
				puts("don't start with #");
			}
			else if(strchr(pch+1,'#')!=NULL && strchr(strchr(pch+1,'#')+1,'#')==NULL && username!= NULL)
			{
				
				// if( send(socket_desc , user_input , strlen(user_input) , 0) < 0)
				// {
				// 	puts("Send failed");
				// 	return 1;
				// }
				// puts("Start transact\n");

				if( send(socket_desc , "List" , 4 , 0) < 0)
				{
					puts("Send failed");
					return 1;
				}

				if( recv(socket_desc, server_reply , 2000 , 0) < 0)
				{
					puts("recv failed");
				}
				
				
				
				char* Payee = strchr(pch+1,'#') +1;
				char myaccount[200] = {0};
				strncpy(myaccount, user_input, pos);
				if(strlen(Payee)== 0)
				{
					puts("please insert payee");
				}

				else if(strcmp(myaccount, username) != 0){
					puts("The one starts transact must be yourself");
				}
				else
				{

					char* result = strstr(server_reply, Payee);
					if(result != NULL)
					{
						char* PayeeIP = strchr(result, '#');
						char* PayeePort = strchr(PayeeIP+1, '#');
						



						int IpLength = (int)(PayeePort - PayeeIP)-1;
						char IP[50]; 
						memset(IP, '\0', sizeof(IP));
						strncpy(IP, PayeeIP+1, IpLength);
						// printf("%d\n", IpLength);
						// printf("%s\n", IP);
						char* PayeePortEnd = strchr(PayeePort, '\n');

						int PortLength = (int)(PayeePortEnd - PayeePort)-1;
						char Port[10]; 
						// printf("%d\n", PortLength);
						memset(Port, '\0', sizeof(Port));
						strncpy(Port, PayeePort+1, PortLength);
						// printf("%s\n", Port);

						

						int sockfd = 0;
						sockfd = socket(AF_INET , SOCK_STREAM , 0);
						struct sockaddr_in info;
						if (sockfd == -1)
						{
							printf("Could not create socket");
						}
						// printf(argc);
						info.sin_addr.s_addr = inet_addr(IP);
						info.sin_family = AF_INET;
						info.sin_port = htons( atoi(Port) );
						if (connect( sockfd, (struct sockaddr *)&info , sizeof(info)) < 0)
						{
							puts("connect error");
							return 1;
						}
						puts("Connected to peer \n");
						if( send(sockfd , user_input , strlen(user_input) , 0) < 0)
						{
							puts("Send failed");
							return 1;
						}
						puts("Successfully send\n");
						puts("awaiting transaction");
						sleep(3);
						
						if( send(socket_desc , "List" , 4 , 0) < 0)
						{
							puts("Send failed");
							return 1;
						}

						if( recv(socket_desc, server_reply , 2000 , 0) < 0)
						{
							puts("recv failed");
						}
						puts(server_reply);

						memset(server_reply, '\0', sizeof(server_reply));
					}
					else{
						puts("Payee not in the list");
					}
				}
			}
			else
			{
				puts("Invalid request, please try again\n");
			}
		}
		else
		{
			if(strlen(user_input) == 4)
			{

				if(user_input[0] == 'L'&&user_input[1] == 'i' &&user_input[2] == 's' &&user_input[3] == 't' )
				{
					if( send(socket_desc , user_input , strlen(user_input) , 0) < 0)
					{
						puts("Send failed");
						return 1;
					}
					puts("Start List\n");

					if( recv(socket_desc, server_reply , 2000 , 0) < 0)
					{
						puts("recv failed");
					}
					puts(server_reply);
					memset(server_reply, '\0', sizeof(server_reply));
				}

				else if(user_input[0] == 'E'&&user_input[1] == 'x' &&user_input[2] == 'i' &&user_input[3] == 't' )
				{
					if( send(socket_desc , user_input , strlen(user_input) , 0) < 0)
					{
						puts("Send failed");
						return 1;
					}
					puts("Start exit\n");
					if( recv(socket_desc, server_reply , 2000 , 0) < 0)
					{
						puts("recv failed");
					}
					// puts(server_reply);

					memset(server_reply, '\0', sizeof(server_reply));
					username = NULL;
					close(client_socket_desc);

					return 0;
				}
			}
			else{
				puts("Invalid request, please try again\n");
			}
		}
		//
		



	}
	close(socket_desc);
	return 0;
	// return 0;
}

// Receiving messages on our port
