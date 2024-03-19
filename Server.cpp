#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <vector>
#include <unistd.h>
#include <openssl/evp.h>
#include <thread>
#include <chrono>
#include "Utility.hpp"
#include <nlohmann/json.hpp>
using namespace std;
using namespace nlohmann;
#define porta 9000

struct protocollo{
    std::string nome;//OK
    std::string nonce;
    std::vector<unsigned char> shared_key;
    const BIGNUM* Public_key_DH;
    DH* S_parameter;
    std::string message;
    std::string crypt_m;//messaggio criptato
    std::string decrypt_m;
};

//aggiunge il campo che voglio
void add_json (json& data, string key, string new_value){
    data[key] = new_value;
}

//rimuove il campo che trova
void remove_json (json& data, string key){
    data.erase(data.find(key));
}

std::string json_to_string (const json& data){
    return data.dump();
}

json string_to_json(std::string stringa){
    return json::parse(stringa);
}

// Calcolo l'hash della password insieme al sale
std::vector<unsigned char> calculatePasswordHash(const std::string& password, const std::vector<unsigned char>& salt) {
    std::vector<unsigned char> hash_password(EVP_MAX_KEY_LENGTH); // Lunghezza massima della chiave
    PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt.data(), salt.size(), 1000, EVP_sha256(), hash_password.size(), hash_password.data());
    return hash_password;
}

// Checker se l'utente che vuole collegarsi esiste -1 se non presente altrimenti restituisce la posizione
int check_user(const std::string username){
    std::ifstream file("Utenti.json");
    if (!file.is_open()) {
        std::cerr << "Impossibile aprire il file JSON." << std::endl;
        return 1;
    }
    json jsonData;
    file >> jsonData;
    
    file.close();
    for(int i = 0; i < jsonData.size(); i++){
        if(jsonData[i]["username"] == username)
        {
            std::cout << "Utente trovato dentro il json " << jsonData[i]["username"] << " == " << username << std::endl;
            return i;
        }
    }
    return -1;
}

// Controllo per l'inserimento corretto della password
bool comparePasswordHash(const std::string& password, const std::string& salt, const std::string& storedHash) {
    // Decodifica il sale memorizzato nel file JSON da esadecimale a vettore di byte
    std::vector<unsigned char> saltBytes = hexToBytes(salt);

    // Calcola l'hash della password fornita utilizzando il sale
    std::vector<unsigned char> calculatedHash = calculatePasswordHash(password, saltBytes);

    // Confronta l'hash calcolato con l'hash memorizzato nel file JSON
    // std::string calculatedHashStr(calculatedHash.begin(), calculatedHash.end());
    std::string hashedPasswordString = bytesToHex(calculatedHash);
    return (hashedPasswordString == storedHash);
}

void protocol(json& data, protocollo& server){
    //std::string json_str;
    // const BIGNUM* Public_key_DH;
    // DH* S_parameter = nullptr;
    // std::vector<unsigned char> shared_secret;
    switch ((int)data["Fase"]) {
        case 1:
            // Ho ricevuto la fase 1 dal client
            std::cout << "Fase 1 -> 2" << std::endl;
            if(check_user(data["Username"]) == -1){
                std::cout << "Utente non trovato" << std::endl;
                exit(-1);
            }else
            {
                std::cout << "Utente trovato" << std::endl;
                server.nome = data["Username"];
            }
            data["Fase"] = 2;
            add_json(data, "Message", "ok");
            server.nonce = generateNonce();
            add_json(data, "Nonce", server.nonce);
            remove_json(data, "Username");
            server.message = json_to_string(data);
            std::cout << "Fase prima di criptare" << server.message << std::endl;
            server.crypt_m = encrypt_private_key_RSA_block(server.message, "Server_private_key.pem");
            std::cout << "Vediamo il messaggio decriptato" << server.message << std::endl;
            std::cout << "Vediamo il messaggio criptato" << server.crypt_m << std::endl;
            break;
        case 2:
            // non ci entro
            std::cout << "Fase 2?" << std::endl;
            break;
        case 3:
            // ricevo dal client la nonce +1 e Ya
            std::cout << "Fase 3 -> 4" << std::endl;
            if(!check_nonce(server.nonce, data["Nonce"])){
                std::cout << "Nonce errata" << std::endl;
                std::cout << "Nonce ricevuta: " << data["Nonce"] << std::endl;
                std::cout << "Nonce salvata: " << server.nonce << std::endl;
                exit(-1);
            }else{
                std::cout << "Nonce ricevuta: " << data["Nonce"] << std::endl;
                std::cout << "Nonce salvata: " << server.nonce << std::endl;
            }
            
            //genero i parametri del server
            server.S_parameter = generateDHFromParamsFile();
            
            //Prendo Yb
            server.Public_key_DH = get_pub_key_DH(server.S_parameter);
            
            //Aggiungo Yb nella struttura data
            add_json(data, "S_DH", bignumToString(server.Public_key_DH));
            
            //dato che ho Ya posso generare il segreto
            server.shared_key = computeSharedSecret(stringToBignum(data["C_DH"]), server.S_parameter);
            
            //rimuovo i campi del json che mi aspetto
            remove_json(data, "C_DH");
            remove_json(data, "Nonce");
            
            //aggiorno la fase
            data["Fase"] = 4;
            
            //aggiungo il timestamp
            add_json(data, "Timestamp", get_current_timestamp());
            std::cout << "Il segreto condiviso è: " << bytesToHex(server.shared_key);
            
            //converto in stringa la struttura json
            server.message = json_to_string(data);
            
            //cripto il messaggio
            server.crypt_m = encrypt_private_key_RSA_block(server.message, "Server_private_key.pem");

            //preparo il server per aspetta i pacchetti crittografati con il segreto condiviso.
            data["Fase"] = 5;
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

int main(int argc, char**argv)
{   
    //inizializzo la struttura json
    json data = {
        {"Username", ""},
        {"Fase", 1}
    };
    //passaggi per settare la connessione
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
            protocollo server;
            json data;
            for(;;)
            {
                //ricevo il messaggio dal client per la prima volta
                std::cout << "Aspetto il client la prima volta" << std::endl;
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
                data = string_to_json(json_str);

                std::cout << "Dati dentro il json (server)" << data.dump(4) << std::endl;
                
                // questa chiamata serve per la prima fase
                protocol(data, server);

                send(newsockfd, server.crypt_m.c_str(), server.crypt_m.length(),0);
                
                std::cout << "Sono a prima di entrare nel secondo ciclo per le fasi successive" << std::endl;
                
                for(;;){

                    std::cout << "Aspetto il client seconda volta" << std::endl;
                    n = recv(newsockfd,recvline,999,0);
                    if(n==0)
                    {
                        std::cout << "errore nella comunicazione" << std::endl;
                        return 0;    
                    }
                    recvline[n] = 0;

                    //metto il dato criptato dentro crypt_m
                    server.crypt_m = std::string(recvline, n);

                    //std::cout << "vediamo il messaggio criptato" << server.crypt_m << std::endl;
                    //decripto il dato e lo metto in decrypt_m
                    server.decrypt_m = decrypt_public_key_RSA_block(server.crypt_m, get_key_path_public(server.nome).c_str());

                    //metto tutto dentro il nostro data json
                    data = string_to_json(server.decrypt_m);

                    std::cout << "vediamo il messaggio decriptato" << data.dump(4) << std::endl;
                    //chiamo il protocollo
                    protocol(data, server);

                    //converto il json in una stringa
                    //json_str = json_to_string(data);

                    // mando la stringa al client
                    send(newsockfd, server.crypt_m.c_str(), server.crypt_m.length(),0);

                    //entriamo nella fase in cui il segreto è stato condiviso e si 
                    if(data["Fase"] == 5){
                        for(;;){

                            std::cout << "Aspetto il client per la comunicazione tramite segreto condiviso" << std::endl;
                            n = recv(newsockfd,recvline,999,0);
                            if(n==0)
                            {
                                std::cout << "errore nella comunicazione" << std::endl;
                                return 0;    
                            }
                            recvline[n] = 0;
                        }
                    }
                    // Visualizzazione dei dati ricevuti
                    // std::cout << "Fase: " << data["Fase"] << std::endl;
                    
                    /*if (received_data["Username"] == "suca"){
                        cout << "ci siamo" << endl;
                        data["Fase"] = 2;
                        remove_json(data, "Username");
                        add_json(data, "nonce", generateNonce());
                        string prova = data.dump();
                        send(newsockfd,sendline,999,0);
                    }*/
                        // break;
                    }
            } 
            return 0; 
        }else{
            close(newsockfd);
        }
    }
}