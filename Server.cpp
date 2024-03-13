#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include "Utility.hpp"
#include <nlohmann/json.hpp>
using namespace std;
using namespace nlohmann;
#define porta 9000

//aggiunge il campo che voglio
void add_json (json& data, string key, string new_value){
    data[key] = new_value;
    std::cout <<data.dump(4) << std::endl;
}
//rimuove campo che trova
void remove_json (json data, string key){
    data.erase(data.find(key));
    std::cout <<data.dump(4) << std::endl;
}
std::string json_to_string (const json& data){
    return data.dump();
}
json string_to_json(std::string stringa){
    return json::parse(stringa);
}

int main(int argc, char**argv)
{   
    json data = {
        {"Username", ""},
        {"Fase", 1}
    };
    int sockfd,newsockfd,n;
    struct sockaddr_in local_addr,remote_addr;
    socklen_t len;
    char sendline[1000];
    char recvline[1000];
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
        newsockfd = accept(sockfd,(struct sockaddr *) &remote_addr, &len);
        if (fork() == 0)
        {
            close(sockfd);
            for(;;)
            {
                //ricevo il messaggio dal client
                n = recv(newsockfd,recvline,999,0);
                if(n==0)
                {
                    std::cout << "errore nella comunicazione" << std::endl;
                    return 0;    
                }
                recvline[n] = 0;
                
                // converto quello che ricevo in una stringa
                std::string json_str(recvline, n);

                // Conversione della stringa JSON in un oggetto JSON
                json data = string_to_json(json_str);

                std::cout << "Dati dentro il json (server)" << data.dump(4) << std::endl;

                data["Fase"] = 2;
                //converto il json in una stringa
                json_str = json_to_string(data);
                // mando la stringa al client
                send(newsockfd, json_str.c_str(), json_str.length(),0);

                // Visualizzazione dei dati ricevuti
                // std::cout << "Nome: " << data["Username"] << std::endl;
                // std::cout << "Fase: " << data["Fase"] << std::endl;
                
                /*if (received_data["Username"] == "suca"){
                    cout << "ci siamo" << endl;
                    data["Fase"] = 2;
                    remove_json(data, "Username");
                    add_json(data, "nonce", generateNonce());
                    string prova = data.dump();
                    send(newsockfd,sendline,999,0);
                }*/
                    break;
            } 
            return 0; 
        }else{
            close(newsockfd);
        }
    }
}