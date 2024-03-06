#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>

#define porta 9000
int main(int argc, char**argv)
{ 
    int sockfd,newsockfd,n;
    struct sockaddr_in local_addr,remote_addr;
    socklen_t len;
    char mesg[1000];
    if((sockfd=socket(AF_INET,SOCK_STREAM,0)) <0)
    { 
        printf("\nErrore nell'apertura del socket");
        return -1;
    }
    memset((char *) &local_addr,0,sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(porta);
    if(bind(sockfd, (struct sockaddr *) &local_addr, sizeof(local_addr))<0)
    { 
        printf("\nErrore nel binding. Errore %d \n", errno);
        return -1;
    }
    listen(sockfd,5);
    for(;;)
    { 
        len = sizeof(remote_addr);
        newsockfd = accept(sockfd,(struct sockaddr *) 
        &remote_addr, &len);
        if (fork() == 0)
        { 
            close(sockfd);
            for(;;)
            { 
                n = recv(newsockfd,mesg,999,0);
                if(n==0) return 0;
                mesg[n] = 0;
                printf("\n Received from %s:%d the following message:%s\n", inet_ntoa(remote_addr.sin_addr), ntohs(remote_addr.sin_port), mesg );
                send(newsockfd,mesg,n,0);
            } 
            return 0; 
        }else{
            close(newsockfd);
        }
    }
}