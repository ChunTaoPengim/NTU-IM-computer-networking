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
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#define SERVER_CERT "server.crt"
#define SERVER_KEY "server.key"

using namespace std;
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

    method = SSLv23_server_method(); // Use SSLv23_server_method for better compatibility
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void* handle_client(void* ssl_socket) ;
string get_server_public_key(SSL_CTX* ctx) {
    X509* cert = SSL_CTX_get0_certificate(ctx);
    if (cert) {
        EVP_PKEY* pubkey = X509_get_pubkey(cert);
        if (pubkey) {
            BIO* out = BIO_new(BIO_s_mem());
            if (out) {
                PEM_write_bio_PUBKEY(out, pubkey);
                char* buffer;
                long size = BIO_get_mem_data(out, &buffer);
                std::string public_key(buffer, size);
                BIO_free(out);
                EVP_PKEY_free(pubkey);
                return public_key;
            } else {
                std::cerr << "Error creating BIO" << std::endl;
            }
            EVP_PKEY_free(pubkey);
        } else {
            std::cerr << "Error getting public key" << std::endl;
        }
    } else {
        std::cerr << "Error getting certificate" << std::endl;
    }

    return ""; // Return an empty string if there's an error
}

string server_public_key = "";
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
struct sockaddr_in cp;
int main(int argc , char **argv) {
    init_openssl();
    SSL_CTX* ctx = create_context();
    string pubkey_str = get_server_public_key(ctx);
    server_public_key = pubkey_str.substr(pubkey_str.find("\n"), pubkey_str.find("-----END PUBLIC KEY-----") - pubkey_str.find("\n") );
    cout << server_public_key << endl;

    int server = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr {};
    addr.sin_family = AF_INET;
    int port = atoi(argv[1]);
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        perror("Error: Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(server, 5) != 0) {
        perror("Error: Unable to listen");
        exit(EXIT_FAILURE);
    }
    int c = sizeof(struct sockaddr_in);

    while (true) {
        int* client = new int(accept(server, (struct sockaddr *)&cp, (socklen_t*)&c));

        char *client_ip = inet_ntoa(cp.sin_addr);
        int client_port = ntohs(cp.sin_port);
        cout << "Client connected: " << client_ip << ":" << client_port << endl;
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, *client);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(*client);
            delete client;
            continue;
        }

        pthread_t thread;
        if (pthread_create(&thread, nullptr, handle_client, ssl) != 0) {
            perror("Error: Unable to create thread");
            close(*client);
            delete client;
            SSL_shutdown(ssl);
            SSL_free(ssl);
        } else {
            pthread_detach(thread);
        }
    }

    close(server);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}
void* handle_client(void* ssl_socket) {
    SSL* ssl = reinterpret_cast<SSL*>(ssl_socket);
    char client_message[8000];
    int bytes;
    int a =0;
    puts("Client connected");
    string username = "";
    while ((bytes = SSL_read(ssl, client_message, sizeof(client_message))) > 0) {
        
		// puts(client_message);
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
				char * message = "210 FAil\n\0";
				SSL_write(ssl , message , strlen(message));
				// strcpy(message, "");
			}
			else{
				char * message = "100 OK\n\0";
				ClientType a;
				a.accountName = client_input.substr(9).c_str() ;
				SSL_write(ssl , message , strlen(message));
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
					string client_ip = inet_ntoa(cp.sin_addr);
					int client_port = ntohs(cp.sin_port);
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
							reply = (to_string(clientList[i].money)+server_public_key);
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
						SSL_write(ssl , reply.c_str() ,reply.length());
						memset(client_message, '\0', 2000);
					}
					else{
						reply = "220 AUTH_FAil\n\0";
						SSL_write(ssl , reply.c_str() ,reply.length());
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
						SSL_write(ssl , reply.c_str() ,reply.length());
						memset(client_message, '\0', 2000);
					}
					else
					{
						string reply = "Transfer Fail\n";
						cout<< reply <<endl;
						SSL_write(ssl , reply.c_str() ,reply.length());
						memset(client_message, '\0', 2000);

					}
				}
			

			}
			else 
			{
				if(client_input == "List")
				{
					bool logged = false;
					

					string reply = "";
					int onlineNumbers = 0;
					for(int i=0; i< clientList.size(); i++)
					{
						if(clientList[i].accountName == username)
						{
							if(clientList[i].login)
							{
								logged = true;
								reply = (to_string(clientList[i].money)+server_public_key);
							}
							
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
						SSL_write(ssl , reply.c_str() ,reply.length());
						memset(client_message, '\0', 2000);
					}
					else{
						reply = "220 please log in first\n\0";
						SSL_write(ssl , reply.c_str() ,reply.length());
						memset(client_message, '\0', 2000);
					}
				}
				else if(client_input == "Exit")
				{
					bool logged = false;
					

					string reply = "";
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
						SSL_write(ssl , reply.c_str() ,reply.length());
						memset(client_message, '\0', 2000);
						pthread_exit(0);
					}
					else{

						reply = "please login before exit";
						SSL_write(ssl , reply.c_str() ,reply.length());
						memset(client_message, '\0', 2000);
					}
				}
				
			}
		}
    }

    ERR_print_errors_fp(stderr);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(*(int*)ssl_socket);
    // delete (int*)ssl_socket;
    pthread_exit(nullptr);
}
