/*User_account serve per aggiungere gli utenti (compresa la generazione delle chiavi RSA).*/
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "Utility.hpp"

using json = nlohmann::json;

//generazione delle chiavi insieme all'utente.
void generate_RSA_key_pair(const std::string& private_key_file, const std::string& public_key_file, int key_length = 2048) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    std::cout << "key_length= " << key_length << std::endl;
    // Crea il contesto per la generazione delle chiavi
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        std::cerr << "Errore durante la creazione del contesto per la generazione delle chiavi" << std::endl;
        return;
    }

    // Inizializza il contesto per la generazione delle chiavi
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        std::cerr << "Errore durante l'inizializzazione del contesto per la generazione delle chiavi" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    // Imposta la lunghezza della chiave
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_length) <= 0) {
        std::cerr << "Errore durante l'impostazione della lunghezza della chiave RSA" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    // Genera la coppia di chiavi
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        std::cerr << "Errore durante la generazione della coppia di chiavi RSA" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    // Salva la chiave privata su file
    FILE *priv_key_file = fopen(private_key_file.c_str(), "wb");
    if (!priv_key_file) {
        std::cerr << "Impossibile aprire il file per la chiave privata" << std::endl;
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    if (PEM_write_PKCS8PrivateKey(priv_key_file, pkey, NULL, NULL, 0, NULL, NULL) == 0) {
        std::cerr << "Errore durante la scrittura della chiave privata" << std::endl;
        fclose(priv_key_file);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    fclose(priv_key_file);

    // Salva la chiave pubblica su file
    FILE *pub_key_file = fopen(public_key_file.c_str(), "wb");
    if (!pub_key_file) {
        std::cerr << "Impossibile aprire il file per la chiave pubblica" << std::endl;
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    if (PEM_write_PUBKEY(pub_key_file, pkey) == 0) {
        std::cerr << "Errore durante la scrittura della chiave pubblica" << std::endl;
        fclose(pub_key_file);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    fclose(pub_key_file);

    // Libera la memoria utilizzata
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    std::cout << "Coppia di chiavi RSA generata con successo" << std::endl;
}

//true se c'è qualcosa, false se vuoto
bool checkEmpityFile(){
    std::ofstream fileUtentiCheck("Utenti.json", std::ios::app);
    if (fileUtentiCheck.is_open()) {
        // Aggiungi una virgola prima di aggiungere il nuovo oggetto JSON se il file non è vuoto
        if (fileUtentiCheck.tellp() != 0) {
            //std::cout << "file 'Utenti.json' non vuoto" << std::endl;
            return true;
        }
        std::cout << "file 'Utenti.json' vuoto" << std::endl;
        fileUtentiCheck.close();
    }
    return false;
}

//rimuovo l'ultima riga che contiene ]
void removeLastLine(){
    std::ifstream inputFileDelete("Utenti.json");
    if (!inputFileDelete.is_open()) {
        std::cerr << "Impossibile aprire il file." << std::endl;
        return;
    }

    // Leggi il contenuto del file
    std::string fileContent((std::istreambuf_iterator<char>(inputFileDelete)), std::istreambuf_iterator<char>());
    inputFileDelete.close();

    // Verifica se il file non è vuoto e se l'ultimo carattere è "]"
    if (!fileContent.empty() && fileContent.back() == ']') {
        // Rimuovi l'ultimo carattere
        fileContent.pop_back();

        // Sovrascrivi il file con il contenuto aggiornato
        std::ofstream outputFile("Utenti.json");
        outputFile << fileContent;
        outputFile.close();

        std::cout << "Carattere ']' rimosso con successo dal file." << std::endl;
    } else {
        std::cout << "Il file non contiene il carattere ']' alla fine." << std::endl;
    }
}

// Funzione per generare un salt casuale
std::vector<unsigned char> generateSalt() {
    std::vector<unsigned char> salt(16); // Salt lungo 16 byte (128 bit)
    RAND_bytes(salt.data(), salt.size());
    return salt;
}

// Funzione per derivare la chiave dalla password con PKCS5_PBKDF2_HMAC
std::vector<unsigned char> deriveKey(std::string& password, const std::vector<unsigned char>& salt) {
    //prendo la password e ne faccio l'hash sha256 e dopo lo rifaccio col sale
    std::cout << "password in chiaro: " << password << std::endl;
    std::string password_hash;
    password_hash = sha256(password);
    std::cout << "Hash della password senza sale: " << password_hash << std::endl;
    std::vector<unsigned char> key(EVP_MAX_KEY_LENGTH); // Lunghezza massima della chiave
    PKCS5_PBKDF2_HMAC(password_hash.c_str(), password_hash.length(), salt.data(), salt.size(), 1000, EVP_sha256(), key.size(), key.data());
    return key;
}

//controllo se l'utente che si vuole aggiungere esiste già
void check_user(const std::string username){
    if(!checkEmpityFile())
    {
        exit(0);
    }
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
            std::cout << "Utente trovato dentro il json " << jsonData[i]["username"] << " == " << username << std::endl;
            std::cout << "Non puoi aggiungere un altro account con lo stesso username." << std::endl;
            exit(-1);
        }
    }
}

int main() {
    
    //aggiungo utenti al file json
    std::string nomeUtente, password;
    
    // Leggi il nome utente e la password inseriti dall'utente
    std::cout << "Inserisci il nome utente: ";
    std::cin >> nomeUtente;
    //check_user(nomeUtente);
    std::cout << "Inserisci la password: ";
    std::cin >> password;

    std::string public_key_path = nomeUtente + "_public_key.pem";
    std::string private_key_path = nomeUtente + "_private_key.pem";

    // std::string password_2 = password;
    // Genera un salt casuale per l'utente
    std::vector<unsigned char> salt = generateSalt();
    // La converto in esadecimale per essere supportato dal json
    std::string saltString = bytesToHex(salt);
    //conviene che prima faccio l'hash della password normale e poi ne rifaccio l'hash col sale

    // Deriva la chiave dalla password con salt utilizzando PKCS5_PBKDF2_HMAC
    std::vector<unsigned char> hashedPassword = deriveKey(password, salt);
    // La converto in esadecimale per essere supportato dal json
    std::string hashedPasswordString = bytesToHex(hashedPassword);

    // Crea un oggetto JSON con i dati dell'utente
    json utente;
    utente["username"] = nomeUtente;
    utente["password"] = hashedPasswordString;
    utente["salt"] = saltString;
    // controllo che il file non sia vuoto e in caso cancello "]"
    if(checkEmpityFile()){
        removeLastLine();
    }
    // Scrivi i dati dell'utente nel file JSON
    std::ofstream fileUtenti("Utenti.json", std::ios::app);
    if (fileUtenti.is_open()) {
        // Aggiungi una virgola prima di aggiungere il nuovo oggetto JSON se il file non è vuoto
        if (fileUtenti.tellp() != 0) {
            removeLastLine();
            fileUtenti << "," << std::endl;
        }else
        {
            fileUtenti << "[" << std::endl; // Aggiungi la parentesi quadra iniziale
        }
        fileUtenti << utente.dump(4);
        fileUtenti << std::endl << "]"; // Aggiungi la parentesi quadra finale
        fileUtenti.close();
        std::cout << "Dati dell'utente aggiunti con successo al file 'Utenti.json'" << std::endl;
        generate_RSA_key_pair(private_key_path, public_key_path, 3072);
        // std::cout << "facciamo un test ora ricalcolo tutto e vedo se matcha" << std::endl;
        // std::vector<unsigned char> hashedPassword_2 = deriveKey(password_2, salt);
        // std::string hashedPasswordString_2 = bytesToHex(hashedPassword_2);
        // if(hashedPasswordString_2 == utente["password"])
        // {
        //     std::cout << "funziona" << std::endl;
        //     std::cout << "password ricalcolata: " << hashedPasswordString_2 << std::endl;
        //     std::cout << "password ricalcolata: " << utente["password"] << std::endl;

        // }else{

        //     std::cout << "non funziona" << std::endl;
        //     std::cout << "password ricalcolata: " << hashedPasswordString_2 << std::endl;
        //     std::cout << "password ricalcolata: " << utente["password"] << std::endl;
        // }
    } else {
        std::cerr << "Errore nell'apertura del file 'Utenti.json'" << std::endl;
    }

    return 0;
}


