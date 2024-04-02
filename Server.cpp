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
//using namespace std;
using namespace nlohmann;
#define porta 9000

struct protocollo{
    std::string nome;//OK
    std::string S_nonce;
    std::vector<unsigned char> shared_key;
    const BIGNUM* Public_key_DH;
    DH* S_parameter = nullptr;
    std::string message;
    std::string crypt_m;//messaggio criptato
    std::string decrypt_m;//messaggio decriptato
    int fase = 1;
    int action = 5;
};

void clear_variable(protocollo data) {
   // Pulisce le stringhe
    data.nome.clear();
    data.S_nonce.clear();
    data.message.clear();
    data.crypt_m.clear();
    data.decrypt_m.clear();
    // Pulisce il vettore di byte
    if(data.shared_key.size() != 0){
        OPENSSL_cleanse(data.shared_key.data(), data.shared_key.size());
        data.shared_key.clear();
    }

    // Pulisce i puntatori
    if(data.Public_key_DH != nullptr)
        data.Public_key_DH = nullptr;

    // Se S_parameter non è nullptr, dealloca la memoria e imposta il puntatore a nullptr
    if (data.S_parameter != nullptr) {
        DH_free(data.S_parameter);
        data.S_parameter = nullptr;
    }
    std::cout << "test3" << std::endl;

}

std::string get_current_timestamp_transfer(){

    time_t rawtime = time(NULL);

    const tm* time_info = localtime(&rawtime);
    char time_buf[80];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", time_info);

    return std::string(time_buf);
}

std::vector<uint8_t> adjust_password(std::vector<uint8_t> hashedPassword){
    std::vector<uint8_t> hashedPassword2 = hashedPassword; // Crea un vettore di 64 elementi uint8_t
    hashedPassword2.insert(hashedPassword2.end(), hashedPassword.begin(), hashedPassword.end());//128
    hashedPassword2.insert(hashedPassword2.end(), hashedPassword.begin(), hashedPassword.end());//192
    hashedPassword2.insert(hashedPassword2.end(), hashedPassword.begin(), hashedPassword.end());//256
    return hashedPassword2;
}

// Checker se l'utente che vuole collegarsi esiste -1 se non presente altrimenti restituisce la posizione
int check_user(const std::string username){
    std::ifstream file("Utenti.json");
    if (!file.is_open()) {
        std::cerr << "Impossibile aprire il file JSON." << std::endl;
        return -1;
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
            return jsonData[i]["password"];
        }
    }
    return "-1";
}

std::string get_content_file(const std::string& username){
    std::string this_file = username + "_history.json";
    //leggo il contenuto di this_username e lo decripto.
    std::ifstream file(this_file, std::ios::binary); // Apri il file in modalità binaria
    if (!file.is_open()) {
        std::cerr << "Impossibile aprire il file." << std::endl;
        return "-1";
    }
    std::vector<unsigned char> this_encryptedData((std::istreambuf_iterator<char>(file)), {});
    std::string this_encryptedString(this_encryptedData.begin(), this_encryptedData.end());
    // Chiudi il file
    file.close();
    // Decifra il contenuto criptato
    std::vector<uint8_t> this_trueKey = adjust_password(hexToBytes(get_hash_passw_file(username)));
    std::string this_decryptedContent = decrypt_AES_GCM(this_trueKey, this_encryptedString);

    return this_decryptedContent;
}
void write_content_file(const std::string& username, const std::string& content_file){
    std::string this_file = username + "_history.json";
    std::string this_cript_m = encrypt_AES_GCM(adjust_password(hexToBytes(get_hash_passw_file(username))), content_file);
    std::ofstream file2(this_file);
    file2.write(this_cript_m.c_str(), this_cript_m.size());
    file2.close();
}
//Get_balance opzione 1
std::string get_user_balance(const std::string username, std::string key){
    std::string decryptedContent = get_content_file(username);

    // Ora puoi usare il contenuto decifrato come desideri
    json jsonData = string_to_json(decryptedContent);
    int x = jsonData["balance"];
    std::string output = std::to_string(x);
    return output;
}

//do transfer opzione 2 (es. lazza manda 20 a marco)
bool Transfer(std::string this_username, std::string other_username, uint amount){
    //controllo che l'utente non voglia trasferirsi soldi a se stesso
    if(this_username == other_username){
        return false;
    }
    //controllo che l'altro utente esiste prima di provare a trasferirgli soldi
    if(check_user(other_username) == -1){
        //std::cout << "Utente non trovato." << std::endl;
        return false;
    }
    // Ora puoi usare il contenuto decifrato come desideri
    json this_jsonData = string_to_json(get_content_file(this_username));
    //leggo il contenuto di other_file e lo decripto
    json other_jsonData = string_to_json(get_content_file(other_username));
    //a questo punto ho decriptato entrambi i file
    //controllo intanto se l'operazione che vuole fare this_username è valida e che abbia abbastanza soldi
    int this_user_balance = this_jsonData["balance"];
    if(this_user_balance < amount)
    {
        //std::cout << "Saldo insufficente per effettuare l'operazione." << std::endl;
        return false;
    }
    //aggiusto il balance dei due utenti
    int other_user_balance = other_jsonData["balance"];
    other_user_balance += amount;
    other_jsonData["balance"] = other_user_balance;
    this_user_balance -= amount;
    this_jsonData["balance"] = this_user_balance;

    json this_user = {
    {"Username", other_username},
    {"Balance", "-"+std::to_string(amount)},
    {"Timestamp", get_current_timestamp_transfer()}
    };

    json other_user = {
    {"Username", this_username},
    {"Balance", "+"+std::to_string(amount)},
    {"Timestamp", get_current_timestamp_transfer()}
    };

    this_jsonData["history"].push_back(this_user);
    other_jsonData["history"].push_back(other_user);

    //scrivo per this utente
    std::string this_scrittura = json_to_string(this_jsonData);
    write_content_file(this_username, this_scrittura);
    //scrivo per other utente
    std::string other_scrittura = json_to_string(other_jsonData);
    write_content_file(other_username, other_scrittura);
    return true;
}

//check history opzione 3
std::string check_history(const std::string username){
    std::string output;
    std::string decryptedContent = get_content_file(username);

    // Ora puoi usare il contenuto decifrato come desideri
    json jsonData = string_to_json(decryptedContent);
    int j;
    // json jsonData;
    // file >> jsonData;
    if(jsonData["history"].size() > 3)//se c'è molto storico
    {
        j = jsonData["history"].size();
        for(int i = (jsonData["history"].size()-3); i < j; i++){
            output.append(jsonData["history"][i].dump(0));
        }
    }else
    {
        for(int i = jsonData["history"].size(); i == 0; i--){
            output.append(jsonData["history"][i].dump(0));
        }
    }
    return output;
}

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
            return jsonData[i]["salt"];
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

            //std::cout << "Dati dentro il json (server)" << data.dump(4) << std::endl;

            //controllo se l'utente esiste
            if(check_user(data["Username"]) == -1){
                std::cout << "Utente non trovato" << std::endl;
                //aggiungo il messaggio di ok
                add_json(data, "Message", "non-ok");
                server.action = 4;
            }else
            {
                std::cout << "Utente trovato" << std::endl;
                server.nome = data["Username"];
                //aggiungo il messaggio di ok
                add_json(data, "Message", "ok");
            }

            //aggiorno la fase
            data["Fase"] = 2;

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
        case 5://faccio il check della password
            std::cout << "Fase 5" << std::endl;
            server.decrypt_m = decrypt_AES_GCM(server.shared_key, server.crypt_m);
            data = string_to_json(server.decrypt_m);
            
            if(comparePasswordHash(data["key"], get_salt_file(server.nome), get_hash_passw_file(server.nome)))
            {
                std::cout << "Passowrd corretta" << std::endl;
                add_json(data, "Message", "Login avvenuto con successo");
            }else{
                add_json(data, "Message", "errore");
                std::cout << "Passoword e/o nome utente sbagliato/i" << std::endl;
                server.action = 4;
            }
            //std::cout << "vediamo il messaggio criptato" << data.dump(4) << std::endl;
            remove_json(data, "key");
            //da qui devo avviare la comunicazione per i vari servizi.
            server.crypt_m = encrypt_AES_GCM(server.shared_key, json_to_string(data));
            //std::cout << "vediamo il messaggio criptato" << server.crypt_m << std::endl;
            server.fase = 6;
            break;
        case 6:
            std::cout << "Fase 6" << std::endl;
            server.decrypt_m = decrypt_AES_GCM(server.shared_key, server.crypt_m);
            data = string_to_json(server.decrypt_m);
            switch((int)data["Action"]){
                case 1: 
                        std::cout << "Questo è il tuo bilancio attuale: " << get_user_balance(server.nome, get_hash_passw_file(server.nome)) << std::endl;
                        data["Message"] = server.nome +" "+get_user_balance(server.nome, get_hash_passw_file(server.nome));
                        break;
                case 2: 
                        std::cout << "Operazione di trasferimento." << std::endl;
                        if(Transfer(server.nome, data["other_username"], string_to_int(data["amount"]))){
                            data["Message"] = "Trasferimento avvenuto con successo";
                        }else{
                            data["Message"] = "Bilancio non sufficente oppure utente non esistente";
                        }
                        remove_json(data, "amount");
                        remove_json(data, "other_username");
                        break;
                case 3: 
                        std::cout << "history" << std::endl;
                        data["Message"] = check_history(server.nome);
                        break;
                case 4: 
                        std::cout << "Logout" << std::endl;
                        data["Message"] = "Logout avvenuto con successo";
                        server.action = 4;
                
            }
            server.crypt_m = encrypt_AES_GCM(server.shared_key, json_to_string(data));
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
    listen(sockfd,0);
    
    for(;;)
    {

        len = sizeof(remote_addr);
        std::cout << "Aspetto un client." << std::endl;
        newsockfd = accept(sockfd,(struct sockaddr *) &remote_addr, &len);
        std::cout << "Ho trovato un client" << std::endl;
        protocollo server;
        json data;
        while(server.action != 4)
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
            send(newsockfd, server.crypt_m.c_str(), server.crypt_m.length(),0);
        } 
        close(newsockfd);
        clear_variable(server);
    }
    close(sockfd);
    return 0;
}