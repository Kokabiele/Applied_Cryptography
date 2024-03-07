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

//encrypt with public key RSA
std::string encrypt_public_key_RSA(const std::string& message, const char *public_key_path) {
    // Determina la lunghezza massima del messaggio criptato
    RSA* rsa_pubkey = nullptr;
    FILE* fp = fopen(public_key_path, "r");
    rsa_pubkey = PEM_read_RSA_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    int max_length = RSA_size(rsa_pubkey);
    std::string encrypted_message(max_length, '\0');

    // Cripta il messaggio con la chiave pubblica
    int encrypted_length = RSA_public_encrypt(message.size(), reinterpret_cast<const unsigned char*>(message.data()), reinterpret_cast<unsigned char*>(const_cast<char*>(encrypted_message.data())), rsa_pubkey, RSA_PKCS1_PADDING);
    if (encrypted_length == -1) {
        std::cerr << "Errore durante la criptazione." << std::endl;
        return "";
    }

    // Ridimensiona il messaggio criptato in base alla lunghezza effettiva
    encrypted_message.resize(encrypted_length);

    return encrypted_message;
}

//encrypt with private key RSA
std::string encrypt_private_key_RSA(const std::string& message, const char* private_key_path) {
    RSA* rsa_privkey = nullptr;
    FILE* fp = fopen(private_key_path, "r");
    rsa_privkey = PEM_read_RSAPrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    int max_length = RSA_size(rsa_privkey);
    unsigned char* encrypted_message = new unsigned char[max_length];

    int encrypted_length = RSA_private_encrypt(message.size(), reinterpret_cast<const unsigned char*>(message.c_str()),
                                               encrypted_message, rsa_privkey, RSA_PKCS1_PADDING);

    if (encrypted_length == -1) {
        std::cerr << "Errore durante la criptazione del messaggio con la chiave privata RSA." << std::endl;
        RSA_free(rsa_privkey);
        delete[] encrypted_message;
        return "";
    }

    std::string encrypted_message_str(reinterpret_cast<char*>(encrypted_message), encrypted_length);

    RSA_free(rsa_privkey);
    delete[] encrypted_message;

    return encrypted_message_str;
}

//decrypt with public key RSA
std::string decrypt_public_key_RSA(const std::string& encrypted_message, const char* public_key_path) {
    RSA* rsa_pubkey = nullptr;
    FILE* fp = fopen(public_key_path, "r");
    rsa_pubkey = PEM_read_RSA_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    int max_length = RSA_size(rsa_pubkey);
    unsigned char* decrypted_message = new unsigned char[max_length];

    int decrypted_length = RSA_public_decrypt(encrypted_message.size(), reinterpret_cast<const unsigned char*>(encrypted_message.c_str()),
                                              decrypted_message, rsa_pubkey, RSA_PKCS1_PADDING);

    if (decrypted_length == -1) {
        std::cerr << "Errore durante la decriptazione del messaggio con la chiave pubblica RSA." << std::endl;
        RSA_free(rsa_pubkey);
        delete[] decrypted_message;
        return "";
    }

    std::string decrypted_message_str(reinterpret_cast<char*>(decrypted_message), decrypted_length);

    RSA_free(rsa_pubkey);
    delete[] decrypted_message;

    return decrypted_message_str;
}

//decrypt with private key RSA
std::string decrypt_private_key_RSA(const std::string& encrypted_message, const char *private_key_path) {
    // Determina la lunghezza massima del messaggio decriptato
    RSA* rsa_privkey = nullptr;
    FILE* fp = fopen(private_key_path, "r");
    rsa_privkey = PEM_read_RSAPrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    int max_length = RSA_size(rsa_privkey);
    std::string decrypted_message(max_length, '\0');

    // Decripta il messaggio
    int decrypted_length = RSA_private_decrypt(encrypted_message.size(), reinterpret_cast<const unsigned char*>(encrypted_message.data()), reinterpret_cast<unsigned char*>(const_cast<char*>(decrypted_message.data())), rsa_privkey, RSA_PKCS1_PADDING);
    if (decrypted_length == -1) {
        std::cerr << "Errore durante la decriptazione." << std::endl;
        return "";
    }

    // Ridimensiona il messaggio decriptato in base alla lunghezza effettiva
    decrypted_message.resize(decrypted_length);

    return decrypted_message;
}

//Hashing with SHA-256
std::string sha256(const std::string& input) {
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    std::string hashedString = "";

    // Inizializza il contesto SHA256
    SHA256_Init(&sha256);
    // Aggiunge i dati della stringa di input al contesto SHA256
    SHA256_Update(&sha256, input.c_str(), input.length());
    // Calcola l'hash SHA256 finale e lo memorizza in 'hash'
    SHA256_Final(hash, &sha256);

    // Converte l'hash binario in una stringa esadecimale
    char hex[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex + (i * 2), "%02x", hash[i]);
    }

    // Converte l'array di caratteri hex in una stringa
    hashedString = hex;

    return hashedString;
}

//check hash: false = 0, true = 1.
bool compareHash(const std::string& inputHash, const std::string& knownHash) {
    return inputHash == knownHash;
}

//get timestamp
std::string get_current_timestamp(){
    time_t rawtime = time(NULL);

    const tm* time_info = localtime(&rawtime);

    char time_buf[80];

    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", time_info);

    return std::string(time_buf);
}

//create a nonce
std::string generateNonce() {
    unsigned char buffer[16];
    
    // Genera una sequenza casuale di byte crittograficamente sicura
    if (RAND_bytes(buffer, 16) != 1) {
        std::cerr << "Errore nella generazione della nonce." << std::endl;
        exit(1);
    }
    
    // Converte la sequenza casuale di byte in una stringa esadecimale
    std::string nonce;
    for (int i = 0; i < 16; ++i) {
        char hex[3];
        sprintf(hex, "%02x", buffer[i]);
        nonce += hex;
    }
    
    return nonce;
}

//increment nonce
std::string incrementNonce(const std::string& nonce) {
    std::string incrementedNonce = nonce;

    // Scorrere i byte della nonce in ordine inverso
    for (int i = incrementedNonce.size() - 1; i >= 0; --i) {
        // Incrementa il valore del byte corrente
        incrementedNonce[i]++;

        // Se il byte non è stato overflowed, termina il loop
        if (incrementedNonce[i] != 0)
            break;
        
        // Se il byte è stato overflowed e non è l'ultimo, continua l'incremento
        // Altrimenti, aggiungi un nuovo byte con valore 1
        if (i != 0)
            continue;
        
        incrementedNonce = '\x01' + incrementedNonce;
    }

    return incrementedNonce;
}

//check nonce ++ : false = 0, true = 1.
bool check_nonce (const std::string& mynonce, const std::string& received_nonce){
    std::string check = incrementNonce(mynonce);
    return check == received_nonce;
}

// Funzione per generare tutti i parametri DH
DH* generateDHFromParamsFile() {
    FILE* params_file = fopen("DH_params.pem", "r");
    if (!params_file) {
        std::cout << "Impossibile aprire il file dei parametri DH." << std::endl;
        return nullptr;
    }
    //estraggo i due parametri pubblici dal file
    DH* dh_params = PEM_read_DHparams(params_file, nullptr, nullptr, nullptr);
    fclose(params_file);

    /*if (!dh_params) {
    std::cout << "dio porco2.5" << std::endl;
        std::cout<< "Impossibile leggere i parametri DH dal file." << std::endl;
        return nullptr;
    }*/

    //faccio un check che tutto sia andato a buon fine
    /*if (!DH_check(dh_params, nullptr)) {
        std::cout << "Parametri DH non validi." << std::endl;
        DH_free(dh_params);
        return nullptr;
    }*/
    // Genera la propria chiave privata(anche quella pubblica) e li metto dentro la struttura DH*
    
    if (!DH_generate_key(dh_params)) {
        std::cout << "Errore nella generazione della chiave DH." << std::endl;
        DH_free(dh_params);
    }

    //DH_free(dh_params);

    return dh_params;
}

// Funzione che presa una struttura restituisce la parte publica del calcolo
const BIGNUM* get_pub_key_DH(DH* dh_params){
    // Ottiene la propria chiave pubblica
    const BIGNUM* pub_key;
    DH_get0_key(dh_params, &pub_key, nullptr);
    return pub_key;
}

// Funzione per estrarre la chiave pubblica DH da un file
const BIGNUM* readDHPublicKeyFromFile() {//const std::string& filename
    // Apri il file in modalità lettura
    std::ifstream file("file_test_dh2.txt");
    if (!file.is_open()) {
        std::cerr << "Errore nell'apertura del file per la lettura." << std::endl;
        return nullptr;
    }

    // Leggi il valore della chiave pubblica DH dal file
    std::string pub_key_str;
    file >> pub_key_str;

    // Chiudi il file
    file.close();

    // Converti la stringa in un oggetto BIGNUM
    BIGNUM* pub_key = BN_new();
    if (!BN_hex2bn(&pub_key, pub_key_str.c_str())) {
        std::cerr << "Errore nella conversione della chiave pubblica in BIGNUM." << std::endl;
        //BN_free(pub_key);
        return nullptr;
    }
    const BIGNUM* pub_key_def = pub_key;
    return pub_key_def;
}

// Funzione per il calcolo della chiave privata del DH
std::vector<unsigned char> computeSharedSecret(const BIGNUM* pub_key_peer, DH* dh_params) {
    // Calcola la lunghezza massima del segreto condiviso
    int shared_secret_len = DH_size(dh_params);
    
    // Alloca memoria per il segreto condiviso
    std::vector<unsigned char> shared_secret(shared_secret_len);

    // Calcola il segreto condiviso
    int computed_len = DH_compute_key(shared_secret.data(), pub_key_peer, dh_params);
    if (computed_len < 0) {
        std::cout << "Errore nel calcolo del segreto condiviso DH." << std::endl;
        // Restituisci un vettore vuoto in caso di errore
        return {};
    }

    // Ridimensiona il vettore al numero di byte effettivamente calcolati
    shared_secret.resize(computed_len);
    
    return shared_secret;
}
