#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include "Utility.hpp"
#include <nlohmann/json.hpp>
using namespace std;

#define porta 9000

int main(int argc, char **argv){
    
    int sockfd, n;
    struct sockaddr_in local_addr, dest_addr;
    char* sendline;
    char recvline[1000];

    if (argc != 3)
    { 
        printf("write username and password!");
        return 1;
    }


	string username = argv[1];
	string password = argv[2];

	if(username.size() > 20 || password.size() > 20){
        printf("Username or password too long");
        return 2;
    }

	cout << "Username: " << username << endl;
	cout << "Password: " << password << endl;

    sockfd=socket(AF_INET,SOCK_STREAM,0);//connessione TCP
    memset( &dest_addr, 0, sizeof(dest_addr));//puliamo tutto mettendo 0
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr("127.0.0.1");//indirizzo
    dest_addr.sin_port = htons(porta);//porta
    connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(dest_addr));
    string exit_command = "";
    while (exit_command != "quit")
    {
        //fase di connessione, l'utente non deve fare nulla
        //Fase 1
        sendline = get_username(argv);
        send(sockfd,sendline,strlen(sendline),0);
        n=recv(sockfd,recvline,999,0);
        recvline[n]=0;
        printf("\nReceived from server %s:%d the following message:%s\n", inet_ntoa(dest_addr.sin_addr),ntohs(dest_addr.sin_port), recvline );
    }
}