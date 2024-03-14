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

using namespace nlohmann;

#define porta 9000

//aggiunge il campo che voglio
void add_json (json& data, std::string key, std::string new_value){
    data[key] = new_value;
    std::cout <<data.dump(4) << std::endl;
}
//rimuove campo che trova
void remove_json (json data, std::string key){
    data.erase(data.find(key));
    std::cout <<data.dump(4) << std::endl;
}
std::string json_to_string (const json& data){
    return data.dump();
}
json string_to_json(std::string stringa){
    return json::parse(stringa);
}
//fase 1 prende l'user all'inizio.
//fase 2 ricevo "ok" e nonce
void protocol(json& data, int&& fase, const int sockfd){
    std::string json_str;
    const BIGNUM* Public_key_DH;
    DH* C_parameter = nullptr;
    switch (fase) {
        case 1:
            // mando solo il nome utente Fase 1
            std::cout << "Fase 1" << std::endl;
            json_str = json_to_string(data);
            send(sockfd, json_str.c_str(), json_str.length(),0);
            break;
        case 2:
            // sto ricevendo dal server "ok" e la nonce, levo ok, metto Ya e nonce +1
            std::cout << "Fase 2 -> 3" << std::endl;
            //rimuovo l'ok
            remove_json(data, "Message");
            //incremento la nonce
            data["Nonce"] = incrementNonce(data["Nonce"]);
            //creo i parametri DH
            C_parameter = generateDHFromParamsFile();
            //Prendo Ya
            Public_key_DH = get_pub_key_DH(C_parameter);
            //Aggiungo Ya nella struttura data
            add_json(data, "C_DH", bignumToString(Public_key_DH));
            data["Fase"] = 3;
            json_str = json_to_string(data);
            send(sockfd, json_str.c_str(), json_str.length(),0);
            break;
        case 3:
            std::cout << "Fase 3" << std::endl;
            std::cout << data.dump(4) << std::endl;
            break;
        case 4:
            std::cout << "Fase 4" << std::endl;
            break;
        case 5:
            std::cout << "Fase 5" << std::endl;
            break;
        case 6:
            std::cout << "Fase 6" << std::endl;
            break;
        default:
            std::cout << "Invalid phase" << std::endl;
            break;
    }
}
int main(int argc, char **argv){
    
    int sockfd, n;
    struct sockaddr_in local_addr, dest_addr;
    //char sendline[1000];
    char recvline[1000];

    if (argc != 3)
    { 
        printf("write username and password!");
        return 1;
    }

    json data = {
        {"Username", argv[1]},
        {"Fase", 1}
    };
	std::string username = argv[1];
	std::string password = argv[2];

	if(username.size() > 20 || password.size() > 20){
        printf("Username or password too long");
        return 2;
    }
	std::cout << "Username: " << username << std::endl;
	std::cout << "Password: " << password << std::endl;

    sockfd=socket(AF_INET,SOCK_STREAM,0);//connessione TCP
    memset( &dest_addr, 0, sizeof(dest_addr));//puliamo tutto mettendo 0
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr("127.0.0.1");//indirizzo
    dest_addr.sin_port = htons(porta);//porta
    connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(dest_addr));
    std::string exit_command = "";
    
    //inizio alcune variabili utili
    std::string json_str;

    while (exit_command != "quit")
    {   

        //controllo in che fase mi trovo e mi comporto di conseguenza
        switch ((int)data["Fase"]) {
        case 1:
        // prima fase, il client manda solo il nome utente ottenuto all'inizio
            std::cout << "Fase: " << data["Fase"] << std::endl;
            protocol(data, (int)data["Fase"], sockfd);
            break;
        case 2:
        // seconda fase, il client riceve {"ok", nonce} e rispondo 
            std::cout << "Fase 2 pacchetto ricevuto: " << data.dump(4) <<std::endl;
            protocol(data, (int)data["Fase"], sockfd);
            break;
        case 3:
        // terza fase, il client manda la nonce + 1 e manda il suo Ya (DH)
            std::cout << "You chose option 3" << std::endl;
            
            break;
        case 4:
        // quarta fase, il client riceve Yb e un timestamp
            std::cout << "You chose option 4" << std::endl;
            break;
        case 5:
        // quinta fase, mediante la chiave di sessione si manda il nome utente e l'hash della password
            std::cout << "You chose option 5" << std::endl;
            break;
        case 6:
        // sesta fase, alla fine della comunicazione si droppa la chiave di sessione.
        default:
            std::cout << "Invalid phase" << std::endl;
            break;
    }

        //converto il json in una stringa prima di mandarlo
        //json_str = json_to_string(data);
        // mando la stringa al server
        //send(sockfd, json_str.c_str(), json_str.length(),0);

        // metto in un vettore i dati ricevuti dal server
        n=recv(sockfd,recvline,999,0);
        recvline[n]=0;

        // converto quello che ricevo in una stringa
        std::string json_str(recvline, n);

        // Conversione della stringa JSON in un oggetto JSON
        data = string_to_json(json_str);

        // Visualizzazione dei dati ricevuti
        //std::cout << "Nome: " << received_data["Username"] << std::endl;
        std::cout << "Fase: " << data["Fase"] << " fine." << std::endl;
        std::cout << "Dati dentro il json(client)" << data.dump(4) << std::endl;
        //break;
    }
}