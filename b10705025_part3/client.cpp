#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <string>
#include <vector>
#include <pthread.h>
#include <unistd.h>
#include<stdio.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
using namespace std;


#define CLIENT_CERT "client.crt"
#define CLIENT_KEY "client.key"

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_client_method(); // Use SSLv23_client_method for better compatibility
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}
SSL_CTX* create_server_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method(); // Use SSLv23_server_method for better compatibility
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX* ctx) {
    // Set options here if needed
}
SSL_CTX* ctx1;
SSL *ssl;
void* receive_thread(void* socket_fd)
{
    int s_fd = *((int*)socket_fd);
	struct sockaddr_in address;
	char buffer[4096] = { 0 };
	int addrlen = sizeof(address);
	
	

	

    while (1) {
		

		


		int* client = new int(accept(s_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen));
		if( client < 0)
		{
			puts("accept failed");
			return 0;
		}
		SSL* ssl2 = SSL_new(ctx1);
        SSL_set_fd(ssl2, *client);
        if (SSL_accept(ssl2) <= 0) {
            ERR_print_errors_fp(stderr);
            close(*client);
            delete client;
            continue;
        }
        

		// I have to receive message from client and send it to server
		int tmp_byte_read = SSL_read(ssl2, buffer, sizeof(buffer) - 1);

    
		// Buffer for decrypted message
		
		
		// memset(decrypted, '\0', sizeof(decrypted));
	
		if( tmp_byte_read > 0)
		{
			// puts(buffer);
			// send it to server

			if( SSL_write(ssl, buffer, strlen(buffer)) < 0)
			{
				puts("Send failed");
				return 0;
			}
			memset(buffer, '\0', sizeof(buffer));
			puts("awaiting transaction");
			SSL_read(ssl, buffer, sizeof(buffer) - 1);
			puts(buffer);
			
		}
		else if(tmp_byte_read == 0)
		{
			puts("Client disconnected");
			break;
		}
		else
		{
			puts("bad");
			break;
		}
		
		
                    
    }
    pthread_exit(0);
}

int socket_desc;

int main(int argc, char **argv) {
    init_openssl();
    SSL_CTX *ctx = create_context();

    configure_context(ctx);
    int serverPort = atoi(argv[2]);

    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    struct sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(serverPort);
    inet_pton(AF_INET, argv[1], &addr.sin_addr);

    if (connect(socket_desc, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        perror("Error: Unable to connect");
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, socket_desc);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
	int client_socket_desc;

	struct sockaddr_in client_server, client;
    string username = "";
    while (true)
    {
		printf("%s",">");
        char user_input[4096];
		scanf("%s", user_input);
		

		char* pch = NULL;
		pch=strchr(user_input,'#');

		if(pch!= NULL)
		{
			
			int pos = (int)(pch - user_input);
			char temp[] = "REGISTER";
			if((pos == 8) && (strncmp(user_input, temp, 8) == 0))
			{
				
				if( SSL_write(ssl, user_input, strlen(user_input)) <0) 
				{
					puts("Send failed");
					return 1;
				}
				puts("Start register\n");
                memset(user_input, 0, sizeof(user_input));
                SSL_read(ssl, user_input, sizeof(user_input) - 1);
				puts(user_input);
				memset(user_input, '\0', sizeof(user_input));
				
			}
			else if(pos == 0)
			{
				puts("don't start with #");
			}
			else if(strchr(pch+1,'#')==NULL && username == "")
			{

				int clientport = atoi(pch+1);

				if(clientport <= 65535 && clientport >=1024)
				{

					if( SSL_write(ssl, user_input, strlen(user_input)) < 0)
					{
						puts("Send failed");
						return 1;
					}
					puts("Start login\n");
					char server_reply[8000] = {0};
					if( SSL_read(ssl, server_reply, sizeof(server_reply) - 1) < 0)
					{
						puts("recv failed");
					}
					puts(server_reply);
					
					
					char* t = strchr(user_input,'#');
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
						// I want to vopy userinput's first length char to username, can't use strcpy because username is a std::string
						username = user_input;
						username = username.substr(0, Length);
						
						cout << "username: " << username << endl;
						memset(user_input, '\0', sizeof(user_input));
						
						client_server.sin_family = AF_INET;
						client_server.sin_addr.s_addr = INADDR_ANY;
						client_server.sin_port = htons( clientport );
							
						//Bind
						if( bind(client_socket_desc,(struct sockaddr *)&client_server , sizeof(client_server)) < 0)
						{
							puts("bind failed\n");
							if( SSL_write(ssl, "Exit", 4) < 0)
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
							username = "";
							close(client_socket_desc);
							puts("can't use this port, try another one");
							SSL_shutdown(ssl);
							SSL_free(ssl);
							close(socket_desc);
							SSL_CTX_free(ctx);
							return 0;
						}
						else{
							init_openssl();
    						ctx1 = create_server_context();
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
			else if(strchr(pch+1,'#')!=NULL && strchr(strchr(pch+1,'#')+1,'#')==NULL && username!= "")
			{
				puts("doing transaction");
				
				char server_reply[8000] = {0};
				if( SSL_write(ssl, "List", 4) < 0)
				{
					puts("Send failed");
					return 1;
				}
				if( SSL_read(ssl, server_reply, sizeof(server_reply) - 1) < 0)
				{
					puts("recv failed");
				}
				// puts(server_reply);
				
				
				char* Payee = strchr(pch+1,'#') +1;
				char myaccount[200] = {0};
				strncpy(myaccount, user_input, pos);
				if(strlen(Payee)== 0)
				{
					puts("please insert payee");
				}

				else if( username != myaccount){
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
						SSL * ssl_peer = SSL_new(ctx);
						SSL_set_fd(ssl_peer, sockfd);

						if (SSL_connect(ssl_peer) <= 0) {
							ERR_print_errors_fp(stderr);
							exit(EXIT_FAILURE);
						}
						puts("Connected to peer \n");
						if( SSL_write(ssl_peer, user_input, strlen(user_input)) < 0)
						{
							puts("Send failed");
							return 1;
						}
						puts("Successfully send\n");
						puts("awaiting transaction");
						
						
						// if( send(socket_desc , "List" , 4 , 0) < 0)
						// {
						// 	puts("Send failed");
						// 	return 1;
						// }

						// if( recv(socket_desc, server_reply , 2000 , 0) < 0)
						// {
						// 	puts("recv failed");
						// }
						// puts(server_reply);

						memset(server_reply, '\0', sizeof(server_reply));
						memset(user_input, '\0', sizeof(user_input));
						// memset(encrypted, '\0', sizeof(encrypted));
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
					if( SSL_write(ssl, user_input, strlen(user_input)) < 0)
					{
						puts("Send failed");
						return 1;
					}
					puts("Start List\n");
                    memset(user_input, 0, sizeof(user_input));
					if( SSL_read(ssl, user_input, sizeof(user_input) - 1) < 0)
                    {
                        puts("recv failed");
                    }

					puts(user_input);
					memset(user_input, '\0', sizeof(user_input));
				}

				else if(user_input[0] == 'E'&&user_input[1] == 'x' &&user_input[2] == 'i' &&user_input[3] == 't' )
				{
					if( SSL_write(ssl, user_input, strlen(user_input)) < 0)
                    {
                        puts("Send failed");
                        return 1;
                    }
	
					puts("Start exit\n");
					memset(user_input, 0, sizeof(user_input));
					if( SSL_read(ssl, user_input, sizeof(user_input) - 1) < 0)
                    {
                        puts("recv failed");
                    }
					// puts(server_reply);
                    puts(user_input);
					memset(user_input, '\0', sizeof(user_input));
					username = "";
					// close(client_socket_desc);
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    close(socket_desc);
                    SSL_CTX_free(ctx);
					return 0;
				}
			}
			else{
				puts("Invalid request, please try again\n");
			}
		}
        
        // char buffer[8000] = {0};
        // std::cout << "Enter message: ";
        // std::cin.getline(buffer, sizeof(buffer));
        // if (strcmp(buffer, "exit") == 0)
        // {
        //     break;
        // }
        // SSL_write(ssl, buffer, strlen(buffer));
        // //clean buffer
        // memset(buffer, 0, sizeof(buffer));
        // SSL_read(ssl, buffer, sizeof(buffer) - 1);
        // std::cout << buffer << std::endl;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(socket_desc);
    SSL_CTX_free(ctx);

    return 0;
}
