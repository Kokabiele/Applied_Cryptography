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
    std::string S_nonce;//OK
    std::string C_nonce;//OK
    std::vector<unsigned char> shared_key;//OK
    const BIGNUM* Public_key_DH;//OK
    DH* C_parameter;//OK
    std::string message;
    std::string crypt_m;
    std::string decrypt_m;
    std::string password;
    int fase = 1;

};

//fase 1 prende l'user all'inizio.
//fase 2 ricevo "ok" e nonce
void protocol(json& data, protocollo& client){
    std::string hash_passw;
    switch (client.fase) {
        case 1:

            // mando il nome utente e una nonce Fase 1
            std::cout << "Fase 1" << std::endl;

            //Salvo il nome utente
            client.nome=data["Username"];

            //genero la nonce del client
            add_json(data, "C_nonce", generateNonce());

            //inserisco la nonce nel json
            client.C_nonce = data["C_nonce"];

            //converto il json in una stringa
            client.message = json_to_string(data);

            //canc
            std::cout << "nome utente ->" << client.nome << std::endl;

            //preparo il client per la fase succesiva
            client.fase = 2;

            //cripto il messaggio con la chiave pubblica del server
            client.crypt_m = encrypt_public_key_RSA_block(client.message, "Server_public_key.pem");
            std::cout << "Qui ci arrivo" << std::endl;
            break;
        case 2:
            // sto ricevendo dal server "ok", la mia nonce +1 e la sua nonce, levo ok, metto Ya e S_nonce +1
            std::cout << "Fase 2 -> 3" << std::endl;

            //decripto il messaggio ottenuto dal server usando la sua chiave pubblica
            client.decrypt_m = decrypt_public_key_RSA_block(client.crypt_m, "Server_public_key.pem");

            // Conversione della stringa JSON in un oggetto JSON
            data = string_to_json(client.decrypt_m);
            //faccio il check della nonce del client che ritorna
            if(!check_nonce(client.C_nonce, data["C_nonce"])){
                std::cout << "Nonce errata protocollo handshake fallito" << std::endl;
                exit(-1);
            }else{
                std::cout << "Nonce salvata: " << client.C_nonce << std::endl;
                std::cout << "Nonce ricevuta(client che torna): " << data["C_nonce"] << std::endl;
            }

            //incremento la nonce del server [potrebbe essere aggiunto il controllo se la nonce del server appena ricevuta è già conosciuta o meno]
            data["S_nonce"] = incrementNonce(data["S_nonce"]);
            
            //rimuovo l'ok
            remove_json(data, "Message");
            
            //rimuovo la mia nonce appena controllata
            remove_json(data, "C_nonce");

            //creo i parametri DH e li salvo nella struct
            client.C_parameter = generateDHFromParamsFile();

            //Prendo Ya
            client.Public_key_DH = get_pub_key_DH(client.C_parameter);

            //Aggiungo Ya nella struttura data
            add_json(data, "C_DH", bignumToString(client.Public_key_DH));

            //aggiorno la fase
            data["Fase"] = 3;

            //converto il json in una stringa
            client.message = json_to_string(data);

            //std::cout << "Fase prima di criptare" << client.message << std::endl; canc
            //cripto il messaggio con la chiave privata del client
            client.crypt_m = encrypt_private_key_RSA_block(client.message, get_key_path_private(client.nome).c_str());

            //std::cout << "Vediamo il messaggio decriptato" << client.message << std::endl;
            //std::cout << "Vediamo il messaggio criptato" << client.crypt_m << std::endl;
            //std::cout << "Vediamo se riesco a descriptarlo subito" << decrypt_public_key_RSA_block(client.crypt_m, get_key_path_public(client.nome).c_str()) << std::endl;
            
            // preparo il client per la fase successiva
            client.fase = 4;
            break;
        case 3:
            std::cout << "Fase 3" << std::endl;
            //std::cout << data.dump(4) << std::endl;
            exit(0);
            break;
        case 4:
            std::cout << "Fase 4" << std::endl;

            //decripto il messaggio ottenuto dal server
            client.decrypt_m = decrypt_public_key_RSA_block(client.crypt_m, "Server_public_key.pem");

            //std::cout << "vedo dati dentro il json: " << client.decrypt_m << std::endl;canc
            // Conversione della stringa JSON in un oggetto JSON
            data = string_to_json(client.decrypt_m);
            
            //controllo se il timestamp è stato inviato al massimo 4 secondi fà
            if(isRecentTimestamp(get_current_timestamp(),data["Timestamp"]) < 5){
                //calcolo il segreto condiviso
                client.shared_key = computeSharedSecret(stringToBignum(data["S_DH"]), client.C_parameter);
                //std::cout << "Il segreto condiviso è: " << bytesToHex(client.shared_key); canc
                //aggiorno la fase
                data["Fase"] = 5;

                //preparo il client per la prossima fase
                client.fase = 5;
                //std::exit(0);
            }else{
                std::cout << "Messaggio troppo vecchio, rischio di replay attack" << std::endl;
                std::exit(-1);
            }
        case 5://il client manda la password(comunicazione tramite segreto condiviso)
            std::cout << "Fase 5, il segreto condiviso è stato calcolato con successo." << std::endl;
            //std::cout << "Dati dentro il json alla fase finale" << data.dump(4) << std::endl;
            remove_json(data, "S_DH");
            remove_json(data, "Timestamp");

            add_json(data, "key", sha256(client.password));

            //std::cout << "password inserita utente: " << data["key"] << std::endl;
            
            //std::cout << "vediamo prima di criptare" << json_to_string(data) << std::endl;
            client.crypt_m = encrypt_AES_GCM(client.shared_key, json_to_string(data));
            //std::cout << "vediamo il messaggio criptato" << client.crypt_m << std::endl;
            client.fase = 6;
            break;
        case 6://il client aspetta di ricevere il messaggio(comunicazione tramite segreto condiviso)
            std::cout << "Fase 6" << std::endl;
            client.decrypt_m = decrypt_AES_GCM(client.shared_key, client.crypt_m);
            std::cout << "vediamo il messaggio decriptato " << client.decrypt_m << std::endl;
            client.crypt_m = encrypt_AES_GCM(client.shared_key, "ciao1");
            std::cout << "vediamo il messaggio criptato" << client.crypt_m << std::endl;
            client.fase = 5;
            exit(0);
            break;
        default:
            std::cout << "Invalid phase" << std::endl;
            break;
    }
}

// void shared_secret_communication(json& data, protocollo& client, int sockfd){
//     char recvline[1000];
//     int n;
//     std::string ciao = encrypt_AES_GCM(client.shared_key, "ciao");
//     std::cout << "vediamo il messaggio criptato" << ciao << std::endl;
//     std::string ciao_d = decrypt_AES_GCM(client.shared_key, ciao);
//     std::cout << "vediamo il messaggio decriptato " << ciao_d << std::endl;

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
// }

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
    client.password = password;
    while (exit_command != "quit")
        
    {   
        protocol(data, client);

        // mando la stringa al server
        send(sockfd, client.crypt_m.c_str(), client.crypt_m.length(),0);
        //aspetto risposta dal server
        // metto in un vettore i dati ricevuti dal server
        n=recv(sockfd,recvline,999,0);
        recvline[n]=0;

        // metto il contenuto del pacchetto dentro message
        client.crypt_m = std::string(recvline, n);

        std::cout << "Fase: " << data["Fase"] << " fine." << std::endl;
        //std::cout << "Dati dentro il json(client)" << data.dump(4) << std::endl;
        //break;
    }
}