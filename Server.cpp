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
    std::string S_nonce;
    std::vector<unsigned char> shared_key;
    const BIGNUM* Public_key_DH;
    DH* S_parameter;
    std::string message;
    std::string crypt_m;//messaggio criptato
    std::string decrypt_m;//messaggio decriptato
    int fase = 1;
};

std::string get_salt_file(const std::string username){
    std::ifstream file("Utenti.json");
    if (!file.is_open()) {
        std::cerr << "Impossibile aprire il file JSON." << std::endl;
        exit(-1);
    }
    json jsonData;
    file >> jsonData;
    
    file.close();
    for(int i = 0; i < jsonData.size(); i++){
        if(jsonData[i]["username"] == username)
        {
            //std::cout << "Utente trovato dentro il json " << jsonData[i]["username"] << " == " << username << std::endl;
            //std::cout << "sale trovato dentro il json " << jsonData[i]["salt"] << std::endl;
            return jsonData[i]["salt"];
        }
    }
    return "-1";
}

std::string get_hash_passw_file(const std::string username){
    std::ifstream file("Utenti.json");
    if (!file.is_open()) {
        std::cerr << "Impossibile aprire il file JSON." << std::endl;
        exit(-1);
    }
    json jsonData;
    file >> jsonData;
    
    file.close();
    for(int i = 0; i < jsonData.size(); i++){
        if(jsonData[i]["username"] == username)
        {
            //std::cout << "Utente trovato dentro il json " << jsonData[i]["username"] << " == " << username << std::endl;
            //std::cout << "password trovato dentro il json " << jsonData[i]["password"] << std::endl;
            return jsonData[i]["password"];
        }
    }
    return "-1";
}

// Calcolo l'hash della password insieme al sale
std::vector<unsigned char> calculatePasswordHash(const std::string& password, const std::vector<unsigned char>& salt) {
    std::vector<unsigned char> key(EVP_MAX_KEY_LENGTH); // Lunghezza massima della chiave
    PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt.data(), salt.size(), 1000, EVP_sha256(), key.size(), key.data());
    return key;
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
    std::string hashedPasswordString = bytesToHex(calculatedHash);
    return (hashedPasswordString == storedHash);
}

void protocol(json& data, protocollo& server){
    switch (server.fase) {
        case 1:
            // Ho ricevuto la fase 1 dal client
            std::cout << "Fase 1 -> 2" << std::endl;

            //decripto il messaggio con la chiave privata del server
            server.decrypt_m = decrypt_private_key_RSA_block(server.crypt_m, "Server_private_key.pem");

            // Conversione della stringa JSON in un oggetto JSON
            data = string_to_json(server.decrypt_m);

            std::cout << "Dati dentro il json (server)" << data.dump(4) << std::endl;

            //controllo se l'utente esiste
            if(check_user(data["Username"]) == -1){
                std::cout << "Utente non trovato" << std::endl;
                exit(-1);
            }else
            {
                std::cout << "Utente trovato" << std::endl;
                server.nome = data["Username"];
            }

            //aggiorno la fase
            data["Fase"] = 2;

            //aggiungo il messaggio di ok
            add_json(data, "Message", "ok");

            //incremento la nonce del client
            data["C_nonce"] = incrementNonce(data["C_nonce"]);

            //genero la nonce del server
            server.S_nonce = generateNonce();

            //aggiungo la nonce del server al json
            add_json(data, "S_nonce", server.S_nonce);

            //rimuovo dal json il nome che non server più
            remove_json(data, "Username");

            //converto il json in una stringa
            server.message = json_to_string(data);

            //cripto il messaggio con la chiave privata del server
            server.crypt_m = encrypt_private_key_RSA_block(server.message, "Server_private_key.pem");

            //preparo il server per la fase successiva
            server.fase = 3;
            break;
        case 2:
            // non ci entro
            std::cout << "Fase 2?" << std::endl;
            break;
        case 3:
            // ricevo dal client la nonce +1 e Ya
            std::cout << "Fase 3 -> 4" << std::endl;
            server.decrypt_m = decrypt_public_key_RSA_block(server.crypt_m, get_key_path_public(server.nome).c_str());

            //metto tutto dentro il nostro data json
            data = string_to_json(server.decrypt_m);

            //controllo la nonce del server
            if(!check_nonce(server.S_nonce, data["S_nonce"])){
                std::cout << "Nonce errata" << std::endl;
                exit(-1);
            }else{
                std::cout << "Nonce ricevuta(server che torna): " << data["S_nonce"] << std::endl;
                std::cout << "Nonce salvata: " << server.S_nonce << std::endl;
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
            remove_json(data, "S_nonce");
            
            //aggiorno la fase
            data["Fase"] = 4;
            
            //aggiungo il timestamp
            add_json(data, "Timestamp", get_current_timestamp());
            //std::cout << "Il segreto condiviso è: " << bytesToHex(server.shared_key);
            
            //converto in stringa la struttura json
            server.message = json_to_string(data);
            
            //cripto il messaggio
            server.crypt_m = encrypt_private_key_RSA_block(server.message, "Server_private_key.pem");

            //preparo il server che aspetta i pacchetti crittografati con il segreto condiviso.
            data["Fase"] = 5;
            server.fase = 5;
            break;
        case 4:
            std::cout << "Fase 4" << std::endl;
            break;
        case 5://faccio il check della password
            std::cout << "Fase 5" << std::endl;
            server.decrypt_m = decrypt_AES_GCM(server.shared_key, server.crypt_m);
            data = string_to_json(server.decrypt_m);
            
            if(comparePasswordHash(data["key"], get_salt_file(server.nome), get_hash_passw_file(server.nome)))
            {
                std::cout << "Passowrd corretta" << std::endl;  
            }else{
                std::cout << "Passoword e/o nome utente sbagliato/i" << std::endl;  
            }
            //da qui devo avviare la comunicazione per i vari servizi.
            server.crypt_m = encrypt_AES_GCM(server.shared_key, "ciao");
            std::cout << "vediamo il messaggio criptato" << server.crypt_m << std::endl;
            server.fase = 6;
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
    listen(sockfd,1);
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
                //ricevo il pacchetto
                n = recv(newsockfd,recvline,999,0);
                if(n==0)
                {
                    std::cout << "errore nella comunicazione" << std::endl;
                    return 0;    
                }
                recvline[n] = 0;
                
                // converto quello che ricevo in una stringa
                server.crypt_m = std::string(recvline, n);

                //chiamo il protocollo
                protocol(data, server);

                //mando il pacchetto al client
                int z = send(newsockfd, server.crypt_m.c_str(), server.crypt_m.length(),0);
                std::cout << "socket number: " << z << std::endl;
            } 
            return 0; 
        }else{
            close(newsockfd);
        }
    }
}