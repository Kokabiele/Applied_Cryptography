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
#include <fstream>
#include "Utility.hpp"
#include <nlohmann/json.hpp>
#include <regex>

using namespace nlohmann;

#define porta 9000

struct protocollo{
    std::string nome;//OK
    std::string C_nonce;//OK
    std::vector<unsigned char> shared_key;//OK
    const BIGNUM* Public_key_DH;//OK
    DH* C_parameter;//OK
    std::string message;
    std::string crypt_m;
    std::string decrypt_m;
    std::string password;
    int action = 5;
    int fase = 1;

};

std::string inserimento_nome_utente(){
    std::string nome_utente;
    bool ok = true;
    do{
        std::cout << "Inserire il nome utente" << std::endl;
        std::cin >> nome_utente;
        bool contains_non_alpha = !std::regex_match(nome_utente, std::regex("^[A-Za-z]+$"));
        if(!contains_non_alpha){
            ok = false;
        }else{
            std::cout << "Nome utente non valido." << std::endl;
        }
    }while(ok);
    return nome_utente;
}

std::string inseriment_password(){
    std::string password;
    bool ok = true;
    do{
        std::cout << "Inserire la password" << std::endl;
        std::cin >> password;
        if(password.size() < 16){
            ok = false;
        }else{
            std::cout << "Password non valida" << std::endl;
        }
    }while(ok);
    return password;
}

void clear_protocollo(protocollo& data) {
    // Pulisce le stringhe
    data.nome.clear();
    data.C_nonce.clear();
    data.message.clear();
    data.crypt_m.clear();
    data.decrypt_m.clear();
    data.password.clear();

    // Pulisce il vettore di byte
    OPENSSL_cleanse(data.shared_key.data(), data.shared_key.size());
    data.shared_key.clear();

    
    // Pulisce i puntatori
    data.Public_key_DH = nullptr;

    // Se C_parameter non è nullptr, dealloca la memoria e imposta il puntatore a nullptr
    if (data.C_parameter != nullptr) {
        DH_free(data.C_parameter);
        data.C_parameter = nullptr;
    }

}

int generate_menu(json& data){
    int input = 5;
    std::string other_username = "";
    std::string amount;
    bool ok = true;
    do{
        std::cout << "Menu:" << std::endl;
        std::cout << "Inserire un valore compreso tra 1 e 4 per eseguire le seguenti azioni: " << std::endl << std::flush;
        std::cout << "1) Balance" << std::endl;
        std::cout << "2) Transfer" << std::endl;
        std::cout << "3) History" << std::endl;
        std::cout << "4) Logout" << std::endl;

        std::cin >> input;
        if (std::cin.fail()) {
            std::cerr << "Input non supportato" << std::endl;
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        }

        if (input < 1 || input > 4) {
            std::cerr << "Azione non supportata" << std::endl;
        }else{
            switch (input){
                case 1:
                        return 1;
                case 2:
                        do{
                            std::cout << "Inserire il nome dell'utente che riceverà il denaro" << std::endl;
                            std::cin >> other_username;
                            bool contains_non_alpha = !std::regex_match(other_username, std::regex("^[A-Za-z]+$"));
                            if(!contains_non_alpha){
                                ok = false;
                            }else{
                                std::cout << "Nome utente non valido." << std::endl;
                            }
                        }while(ok);
                        add_json(data, "other_username", other_username);
                        ok = true;
                        do{
                            std::cout << "Inserire la quantità di denaro che si vuole trasferire" << std::endl;
                            std::cin >> amount;
                            bool contains_non_alpha1 = !std::regex_match(amount, std::regex("^[0-9]+$"));
                            if(!contains_non_alpha1){
                                ok = false;
                            }else{
                                std::cout << "Quantià inserita non valida." << std::endl;
                            }
                        add_json(data, "amount", amount);   
                        }while(ok);
                        return 2;
                case 3:
                        return 3;
                case 4:
                        return 4;

            }
        }
    }while(input < 1 || input > 4);
    return input;
}

void check_history(const std::string username){
    std::string nome_file = username + "_history.json";
    std::ifstream file(nome_file);
    if (!file.is_open()) {
        std::cerr << "Impossibile aprire il file JSON." << std::endl;
        exit(-1);
    }
    int j;
    json jsonData;
    file >> jsonData;
    if(jsonData["history"].size() > 10){
        j = 10;
    }else{
        j = jsonData["history"].size();
    }
    file.close();
    for(int i = 0; i < j; i++){
        std::cout << jsonData["history"][i].dump(4) << std::endl;
    }
}

//fase 1 prende l'user all'inizio.
//fase 2 ricevo "ok" e nonce
void protocol(json& data, protocollo& client){
    int input;
    std::istringstream iss;
    std::string line;
    switch (client.fase) {
        case 1:

            // mando il nome utente e una nonce Fase 1
            //std::cout << "Fase 1" << std::endl;

            //Salvo il nome utente
            client.nome=data["Username"];

            //genero la nonce del client
            add_json(data, "C_nonce", generateNonce());

            //inserisco la nonce nel json
            client.C_nonce = data["C_nonce"];

            //converto il json in una stringa
            client.message = json_to_string(data);

            //canc
            //std::cout << "nome utente ->" << client.nome << std::endl;

            //preparo il client per la fase succesiva
            client.fase = 2;

            //cripto il messaggio con la chiave pubblica del server
            client.crypt_m = encrypt_public_key_RSA_block(client.message, "Server_public_key.pem");
            //std::cout << "Qui ci arrivo" << std::endl;
            break;
        case 2:
            // sto ricevendo dal server "ok", la mia nonce +1 e la sua nonce, levo ok, metto Ya e S_nonce +1
            //std::cout << "Fase 2 -> 3" << std::endl;

            //decripto il messaggio ottenuto dal server usando la sua chiave pubblica
            client.decrypt_m = decrypt_public_key_RSA_block(client.crypt_m, "Server_public_key.pem");

            // Conversione della stringa JSON in un oggetto JSON
            data = string_to_json(client.decrypt_m);
            //faccio il check della nonce del client che ritorna
            if(!check_nonce(client.C_nonce, data["C_nonce"])){
                //std::cout << "Nonce errata protocollo handshake fallito" << std::endl;
                exit(-1);
            }else{
                //std::cout << "Nonce salvata: " << client.C_nonce << std::endl;
                //std::cout << "Nonce ricevuta(client che torna): " << data["C_nonce"] << std::endl;
            }

            //incremento la nonce del server [potrebbe essere aggiunto il controllo se la nonce del server appena ricevuta è già conosciuta o meno]
            data["S_nonce"] = incrementNonce(data["S_nonce"]);
            
            //rimuovo l'ok
            if(data["Message"] == "ok"){
                remove_json(data, "Message");
            }else
            {
                std::cout << "Nome utente errato o non esistente" << std::endl;
                exit(-1);
            }
            
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
        case 4:
            //std::cout << "Fase 4" << std::endl;

            //decripto il messaggio ottenuto dal server
            client.decrypt_m = decrypt_public_key_RSA_block(client.crypt_m, "Server_public_key.pem");

            //std::cout << "vedo dati dentro il json: " << client.decrypt_m << std::endl;
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
            //std::cout << "Fase 5, il segreto condiviso è stato calcolato con successo." << std::endl;
            //std::cout << "Dati dentro il json alla fase finale" << data.dump(4) << std::endl;
            remove_json(data, "S_DH");
            remove_json(data, "Timestamp");

            add_json(data, "key", sha256(inseriment_password()));
            //std::cout << "password inserita utente: " << data["key"] << std::endl;
            
            client.crypt_m = encrypt_AES_GCM(client.shared_key, json_to_string(data));
            //std::cout << "vediamo il messaggio criptato" << client.crypt_m << std::endl;
            client.fase = 6;
            break;
        case 6://il client aspetta di ricevere il messaggio(comunicazione tramite segreto condiviso)
            //std::cout << "Fase 6" << std::endl;
            //Decripto il messaggio da stampare ottenuto dal server
            client.decrypt_m = decrypt_AES_GCM(client.shared_key, client.crypt_m);
            //lo mostro a schermo
            //lo converto
            data = string_to_json(client.decrypt_m);

            if(data["Message"] == "errore")
            {
                std::cout << "Passoword e/o nome utente sbagliato/i" << std::endl;
                exit(-1);
            }
            //lo mostro pulito a schermo
            //std::cout << data.dump(4) << std::endl;
            client.message = data["Message"];
            switch(client.action){
                case 1: 
                        std::cout << "Questo è il tuo bilancio attuale: " << client.message << "€" << std::endl;
                        break;
                case 2: 
                        std::cout << client.message << std::endl;
                        break;
                case 3: 
                        //pulisco l'input
                        std::cout << "history" << std::endl;
                        client.message.erase(std::remove_if(client.message.begin(), client.message.end(), [](char c) { return c == '\"'; }), client.message.end());
                        std::replace(client.message.begin(), client.message.end(), '{', ' ');
                        std::replace(client.message.begin(), client.message.end(), '}', ' ');
                        std::replace(client.message.begin(), client.message.end(), ',', ' ');
                        std::cout << "Il risultato della tua operazione è: " << client.message << std::endl;
                        break;
                case 4: 
                        std::cout << "Logout" << std::endl;
                        //std::cout << "Il risultato della tua operazione è: " << data["Action"] << std::endl;
                        exit(1);
                case 5: break;
            }
            //scelgo l'azione da fare
            input = generate_menu(data);
            //l'aggiungo al mio json
            add_json(data, "Action", std::to_string(input));
            data["Action"] = input;
            client.action = input;
            //std::cout << "Prima di mandare l'azione al server " << data.dump(4) << std::endl;
            //lo converto e lo cripto
            client.message = json_to_string(data);
            client.crypt_m = encrypt_AES_GCM(client.shared_key, client.message);

            //exit(0);
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
	std::string username = inserimento_nome_utente();
    json data = {
        {"Username", username},
        {"Fase", 1}
    };

    sockfd=socket(AF_INET,SOCK_STREAM,0);//connessione TCP
    memset( &dest_addr, 0, sizeof(dest_addr));//puliamo tutto mettendo 0
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr("127.0.0.1");//indirizzo
    dest_addr.sin_port = htons(porta);//porta
    connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(dest_addr));
    std::string exit_command = "";
    
    //inizio alcune variabili utili
    protocollo client;
    while (client.action != 4)     
    {   
        protocol(data, client);

        // mando la stringa al server
        send(sockfd, client.crypt_m.c_str(), client.crypt_m.length(),0);
        //aspetto risposta dal server
        // metto in un vettore i dati ricevuti dal server
        n=recv(sockfd,recvline,999,0);
        if(n==0)
            {
                std::cout << "Il server ha rifiutato la connessione" << std::endl;
                return 0;    
            }
        recvline[n]=0;
        // metto il contenuto del pacchetto dentro message
        client.crypt_m = std::string(recvline, n);

        //std::cout << "Fase: " << data["Fase"] << " fine." << std::endl;
        //std::cout << "Dati dentro il json(client)" << data.dump(4) << std::endl;
        //break;
    }
    close(sockfd);
return 1;
}