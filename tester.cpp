#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/dh.h>
#include <string>
#include <vector>
#include <fstream>
#include <openssl/err.h>

std::string generateNonce() {
    unsigned char buffer[16];
    
    // Genera una sequenza casuale di byte crittograficamente sicura
    if (RAND_bytes(buffer, 16) != 1) {
        std::cerr << "Errore nella generazione della nonce." << std::endl;
        exit(1);
    }
    // std::cout << buffer << std::endl;
    // Converte la sequenza casuale di byte in una stringa esadecimale
    std::string nonce;
    for (int i = 0; i < 16; ++i) {
        char hex[3];
        sprintf(hex, "%02x", buffer[i]);
        nonce += hex;
    }
    //std::cout << nonce << std::endl;
    return nonce;
}

//funziona, in questo modo posso aggiungere campi al json
// void modifica_json (json data, string campo1, string campo2){
//     data.push_back(json::object_t::value_type(campo1, campo2));
//     std::cout <<data.dump(4) << std::endl;
// }
// rimuove un campo a scelta
// void remove_json (json data, string campo){
//     cout << "test" << endl;
//     data.erase(data.find(campo));
//     std::cout <<data.dump(4) << std::endl;
// }
/*
    Nel main ci sarà
    json data = {
        {"Username", ""}
    };
    string prova = "mela";
    modifica_json(data, "suca", prova);
*/
int main(int argc, char **argv){
    for(;;){
        std::cout << generateNonce() << std::endl;
        //generateNonce();
    }
}