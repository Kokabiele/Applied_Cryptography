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

struct protocollo{
    std::string nome;//OK
    std::string nonce;//OK
    std::vector<unsigned char> shared_key;//OK
    const BIGNUM* Public_key_DH;//OK
    DH* C_parameter;//OK
    std::string message;
    std::string crypt_m;
    std::string decrypt_m;

};
//aggiunge il campo che voglio
void add_json (json& data, std::string key, std::string new_value){
    data[key] = new_value;
    //std::cout <<data.dump(4) << std::endl;
}
//rimuove campo che trova
void remove_json (json& data, std::string key){
    data.erase(data.find(key));
}
std::string json_to_string (const json& data){
    return data.dump();
}
json string_to_json(std::string stringa){
    return json::parse(stringa);
}

//fase 1 prende l'user all'inizio.
//fase 2 ricevo "ok" e nonce
void protocol(json& data, protocollo& client){
    int test_timestamp;
    switch ((int)data["Fase"]) {
        case 1:
            // mando solo il nome utente Fase 1
            std::cout << "Fase 1" << std::endl;
            client.nome=data["Username"];
            client.crypt_m = json_to_string(data);
            std::cout << "nome utente ->" << client.nome << std::endl;
            // client.crypt_m = encrypt_private_key_RSA(client.message, get_key_path(client.nome));
            break;
        case 2:
            // sto ricevendo dal server "ok" e la nonce, levo ok, metto Ya e nonce +1
            std::cout << "Fase 2 -> 3" << std::endl;
            //incremento la nonce
            data["Nonce"] = incrementNonce(data["Nonce"]);
            //rimuovo l'ok
            remove_json(data, "Message");
            //creo i parametri DH e li salvo nella struct
            client.C_parameter = generateDHFromParamsFile();
            //Prendo Ya
            client.Public_key_DH = get_pub_key_DH(client.C_parameter);
            //Aggiungo Ya nella struttura data
            add_json(data, "C_DH", bignumToString(client.Public_key_DH));
            data["Fase"] = 3;
            client.message = json_to_string(data);
            //std::cout << "Fase prima di criptare" << client.message << std::endl;
            client.crypt_m = encrypt_private_key_RSA_block(client.message, get_key_path_private(client.nome).c_str());
            //std::cout << "Vediamo il messaggio decriptato" << client.message << std::endl;
            std::cout << "Vediamo il messaggio criptato" << client.crypt_m << std::endl;
            std::cout << "Vediamo se riesco a descriptarlo subito" << decrypt_public_key_RSA_block(client.crypt_m, get_key_path_public(client.nome).c_str()) << std::endl;
            break;
        case 3:
            std::cout << "Fase 3" << std::endl;
            //std::cout << data.dump(4) << std::endl;
            exit(0);
            break;
        case 4:
            std::cout << "Fase 4" << std::endl;
            //controllare il timestamp se la differenza tra i due è minore di 5 secondi va bene
            if(isRecentTimestamp(get_current_timestamp(),data["Timestamp"]) < 5){
                //posso calcolare il segreto condiviso
                client.shared_key = computeSharedSecret(stringToBignum(data["S_DH"]), client.C_parameter);
                std::cout << "Il segreto condiviso è: " << bytesToHex(client.shared_key);
                data["Fase"] = 5;
                //std::exit(0);
            }else{
                std::cout << "Messaggio troppo vecchio, rischio di replay attack" << std::endl;
                std::exit(-1);
            }
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

void shared_secret_communication(json& data, protocollo& client, int sockfd){
    char recvline[1000];
    int n;
    std::string ciao = encrypt_AES_GCM(client.shared_key, "ciao");
    std::cout << "vediamo il messaggio criptato" << ciao << std::endl;
    std::string ciao_d = decrypt_AES_GCM(client.shared_key, ciao);
    std::cout << "vediamo il messaggio decriptato " << ciao_d << std::endl;

    // for(;;){

    //     send(sockfd, ciao.c_str(), ciao.length(),0);
    //     // if((int)data["Fase"]==3)
    //     // {
    //     //     return 1;
    //     // }
    //     //aspetto risposta dal server
    //     // metto in un vettore i dati ricevuti dal server
    //     n=recv(sockfd,recvline,999,0);
    //     recvline[n]=0;
    // }
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
    std::string key_pem = "_private_key.pem";
	std::string username = argv[1];
	std::string password = argv[2];
    std::string test = (username.append("ciao")).c_str();
    //char* = (username.append("ciao")).c_str();
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
    protocollo client;
    std::string json_str;
    std::string encrypted_msg;
    const BIGNUM* Public_key_DH;
    DH* C_parameter = nullptr;
    std::vector<unsigned char> shared_secret;
    while (exit_command != "quit")
        
    {   
        protocol(data, client);

        if(data["Fase"] == 5){
            std::cout << "comunicazione tramite segreto condiviso" << std::endl;
            shared_secret_communication(data, client, sockfd);
        }
        //converto il json in una stringa prima di mandarlo
        //json_str = json_to_string(data);

        // mando la stringa al server
        send(sockfd, client.crypt_m.c_str(), client.crypt_m.length(),0);
        // if((int)data["Fase"]==3)
        // {
        //     return 1;
        // }
        //aspetto risposta dal server
        // metto in un vettore i dati ricevuti dal server
        n=recv(sockfd,recvline,999,0);
        recvline[n]=0;

        // metto il contenuto del pacchetto dentro message
        client.crypt_m = std::string(recvline, n);

        //decripto il messaggio ottenuto dal server
        client.decrypt_m = decrypt_public_key_RSA_block(client.crypt_m, "Server_public_key.pem");

        // converto quello che ricevo in una stringa
        // std::string json_str(recvline, n);

        // Conversione della stringa JSON in un oggetto JSON
        data = string_to_json(client.decrypt_m);

        // Visualizzazione dei dati ricevuti
        //std::cout << "Nome: " << received_data["Username"] << std::endl;
        std::cout << "Fase: " << data["Fase"] << " fine." << std::endl;
        //std::cout << "Dati dentro il json(client)" << data.dump(4) << std::endl;
        //break;
    }
}
        /*
        switch ((int)data["Fase"]) {
            case 1:
                // mando solo il nome utente Fase 1
                std::cout << "Fase 1" << std::endl;
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
                break;
            case 3:
                std::cout << "Fase 3" << std::endl;
                break;
            case 4:
                std::cout << "Fase 4" << std::endl;
                shared_secret = computeSharedSecret(stringToBignum(data["S_DH"]), C_parameter);
                std::cout << "Il segreto condiviso è: " << bytesToHex(shared_secret);
                return 0;
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
        }*/