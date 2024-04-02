#include <iostream>
#include <sstream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/dh.h>
#include <string>
#include <vector>
#include <fstream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <nlohmann/json.hpp>
using namespace nlohmann;



std::string decrypt_AES_GCM_file(const std::vector<unsigned char>& key, const std::string& encrypted_file_path) {
    // Verifica che la chiave sia di lunghezza corretta
    if (key.size() != 32) {
        std::cerr << "La lunghezza della chiave deve essere di 32 byte (256 bit)" << std::endl;
        return "";
    }

    // Apri il file criptato in modalità binaria
    std::ifstream encrypted_file(encrypted_file_path, std::ios::binary);
    if (!encrypted_file.is_open()) {
        std::cerr << "Impossibile aprire il file criptato: " << encrypted_file_path << std::endl;
        return "";
    }

    // Leggi il contenuto del file criptato in un vettore di byte
    std::vector<unsigned char> encrypted_data(std::istreambuf_iterator<char>(encrypted_file), {});

    // Estrai il vettore di inizializzazione (IV) e il tag di autenticazione dal file criptato
    unsigned char iv[12];
    unsigned char tag[16];
    std::copy(encrypted_data.begin(), encrypted_data.begin() + 12, iv);
    std::copy(encrypted_data.end() - 16, encrypted_data.end(), tag);

    // Calcola la lunghezza del ciphertext
    int ciphertext_len = encrypted_data.size() - 12 - 16;

    // Ottieni il ciphertext dal file criptato
    unsigned char* ciphertext = encrypted_data.data() + 12;

    // Crea un buffer per il plaintext decriptato
    std::vector<unsigned char> plaintext(ciphertext_len);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Errore durante l'inizializzazione del contesto di decrittografia." << std::endl;
        return "";
    }

    // Inizializza il contesto di decrittografia per AES in modalità GCM
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        std::cerr << "Errore durante l'inizializzazione del contesto di decrittografia AES-GCM." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    // Imposta la chiave, il vettore di inizializzazione e il tag di autenticazione
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv) != 1) {
        std::cerr << "Errore durante l'impostazione della chiave, del vettore di inizializzazione e del tag di autenticazione." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    // Decritta il ciphertext
    int len = 0;
    int plaintext_len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len) != 1) {
        std::cerr << "Errore durante la decrittografia del file." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = len;

    // Completa l'operazione di decrittografia
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        std::cerr << "Errore durante il completamento dell'operazione di decrittografia." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Converte il plaintext decriptato in una stringa
    std::string decrypted_message(reinterpret_cast<char*>(plaintext.data()), plaintext_len);

    return decrypted_message;
}


//test per criptazioni con segreto condiviso
void handleErrors() {
    std::cerr << "Errore crittografico" << std::endl;
    ERR_print_errors_fp(stderr);
    exit(1);
}

// funzione per criptare
std::string encrypt_AES_GCM(const std::vector<unsigned char>& key, const std::string& plaintext) {
    // Verifica che la chiave sia di lunghezza corretta
    if (key.size() != 256) {
        std::cerr << "La lunghezza della chiave deve essere di 32 byte (256 bit)" << std::endl;
        return "";
    }

    // Genera un vettore di inizializzazione (IV) casuale di 12 byte
    unsigned char iv[12];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        handleErrors();
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleErrors();
    }

    // Inizializza il contesto di crittografia per AES in modalità GCM
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        handleErrors();
    }

    // Imposta la chiave e il vettore di inizializzazione
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv) != 1) {
        handleErrors();
    }

    // Cripta il messaggio
    int len = 0;
    int ciphertext_len = 0;
    unsigned char ciphertext[plaintext.size() + EVP_MAX_BLOCK_LENGTH]; // Dimensione massima del ciphertext
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size()) != 1) {
        handleErrors();
    }
    ciphertext_len = len;

    // Completa l'operazione di crittografia
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        handleErrors();
    }
    ciphertext_len += len;

    // Recupera il tag di autenticazione
    unsigned char tag[16]; // Dimensione del tag per AES-GCM
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        handleErrors();
    }

    EVP_CIPHER_CTX_free(ctx);

    // Concatena IV, ciphertext e tag per creare il messaggio cifrato
    std::string encrypted_message(reinterpret_cast<char*>(iv), sizeof(iv));
    encrypted_message += std::string(reinterpret_cast<char*>(ciphertext), ciphertext_len);
    encrypted_message += std::string(reinterpret_cast<char*>(tag), 16);

    return encrypted_message;
}

//decripta
std::string decrypt_AES_GCM(const std::vector<unsigned char>& key, const std::string& encrypted_message) {
    // Verifica che la chiave sia di lunghezza corretta
    if (key.size() != 256) {
        std::cerr << "La lunghezza della chiave deve essere di 256 byte" << std::endl;
        return "";
    }

    // Recupera IV, ciphertext e tag dal messaggio cifrato
    std::string iv(encrypted_message.begin(), encrypted_message.begin() + 12);
    std::string ciphertext(encrypted_message.begin() + 12, encrypted_message.end() - 16);
    std::string tag(encrypted_message.end() - 16, encrypted_message.end());

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleErrors();
    }

    // Inizializza il contesto di decrittografia per AES in modalità GCM
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        handleErrors();
    }

    // Imposta la chiave e il vettore di inizializzazione
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), reinterpret_cast<const unsigned char*>(iv.c_str())) != 1) {
        handleErrors();
    }

    // Imposta il tag di autenticazione
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, reinterpret_cast<void*>(const_cast<char*>(tag.c_str()))) != 1) {
        handleErrors();
    }

    // Decifra il messaggio
    int len = 0;
    int plaintext_len = 0;
    unsigned char plaintext[encrypted_message.size() - 12 - 16]; // Dimensione massima del plaintext
    if (EVP_DecryptUpdate(ctx, plaintext, &len, reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size()) != 1) {
        handleErrors();
    }
    plaintext_len = len;

    // Completa l'operazione di decrittografia
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        handleErrors();
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Restituisce il plaintext decifrato
    return std::string(reinterpret_cast<char*>(plaintext), plaintext_len);
}

void encrypt_AES_GCM_file(const std::vector<unsigned char>& key, const std::string& input_file_path, const std::string& output_file_path) {

}


//crypt e decrypt a blocchi.
std::string encrypt_private_key_RSA_block(const std::string& message, const char* private_key_path) {
    RSA* rsa_privkey = nullptr;
    FILE* fp = fopen(private_key_path, "r");
    rsa_privkey = PEM_read_RSAPrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!rsa_privkey) {
        std::cerr << "Errore durante la lettura della chiave privata RSA." << std::endl;
        return "";
    }

    // Ottieni la dimensione massima dei blocchi crittografici
    int max_length = RSA_size(rsa_privkey);
    int block_size = max_length - RSA_PKCS1_PADDING_SIZE; // dimensione massima del blocco crittografico

    std::string encrypted_message;

    // Cripta i blocchi della stringa message
    int offset = 0;
    while (offset < message.size()) {
        // Calcola la dimensione del blocco da criptare
        int size = std::min(block_size, static_cast<int>(message.size()) - offset);
        std::string block = message.substr(offset, size);

        // Cripta il blocco corrente
        unsigned char* encrypted_block = new unsigned char[max_length];
        int encrypted_length = RSA_private_encrypt(size, reinterpret_cast<const unsigned char*>(block.data()),
                                                   encrypted_block, rsa_privkey, RSA_PKCS1_PADDING);
        if (encrypted_length == -1) {
            std::cerr << "Errore durante la criptazione del blocco." << std::endl;
            RSA_free(rsa_privkey);
            delete[] encrypted_block;
            return "";
        }

        // Aggiungi il blocco criptato al messaggio criptato completo
        encrypted_message.append(reinterpret_cast<char*>(encrypted_block), encrypted_length);

        // Dealloca la memoria del blocco criptato
        delete[] encrypted_block;

        // Passa al prossimo blocco
        offset += size;
    }

    // Libera la memoria della chiave RSA
    RSA_free(rsa_privkey);

    return encrypted_message;
}

std::string decrypt_private_key_RSA_block(const std::string& encrypted_message, const char* private_key_path) {
    RSA* rsa_privkey = nullptr;
    FILE* fp = fopen(private_key_path, "r");
    rsa_privkey = PEM_read_RSAPrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!rsa_privkey) {
        std::cerr << "Errore durante la lettura della chiave privata RSA." << std::endl;
        return "";
    }

    // Ottieni la dimensione massima dei blocchi crittografici
    int max_length = RSA_size(rsa_privkey);

    std::string decrypted_message;

    // Decripta i blocchi della stringa encrypted_message
    int offset = 0;
    while (offset < encrypted_message.size()) {
        // Decripta il blocco corrente
        unsigned char* decrypted_block = new unsigned char[max_length];
        int decrypted_length = RSA_private_decrypt(max_length, reinterpret_cast<const unsigned char*>(encrypted_message.data() + offset),
                                                   decrypted_block, rsa_privkey, RSA_PKCS1_PADDING);
        if (decrypted_length == -1) {
            std::cerr << "Errore durante la decriptazione del blocco." << std::endl;
            RSA_free(rsa_privkey);
            delete[] decrypted_block;
            return "";
        }

        // Aggiungi il blocco decriptato al messaggio decriptato completo
        decrypted_message.append(reinterpret_cast<char*>(decrypted_block), decrypted_length);

        // Dealloca la memoria del blocco decriptato
        delete[] decrypted_block;

        // Passa al prossimo blocco
        offset += max_length;
    }

    // Libera la memoria della chiave RSA
    RSA_free(rsa_privkey);

    return decrypted_message;
}

std::string decrypt_public_key_RSA_block(const std::string& encrypted_message, const char* public_key_path) {
    RSA* rsa_pubkey = nullptr;
    FILE* fp = fopen(public_key_path, "r");
    rsa_pubkey = PEM_read_RSA_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    //std::cout << "path chiave pubblica: " << public_key_path << std::endl;
    if (!rsa_pubkey) {
        std::cerr << "Errore durante la lettura della chiave pubblica RSA." << std::endl;
        return "";
    }

    // Ottieni la dimensione massima dei blocchi crittografici
    int max_length = RSA_size(rsa_pubkey);
    std::string decrypted_message;

    // Decripta i blocchi della stringa encrypted_message
    int offset = 0;
    while (offset < encrypted_message.size()) {
        // Decripta il blocco corrente
        unsigned char* decrypted_block = new unsigned char[max_length];
        int decrypted_length = RSA_public_decrypt(max_length, reinterpret_cast<const unsigned char*>(encrypted_message.data() + offset),
                                                  decrypted_block, rsa_pubkey, RSA_PKCS1_PADDING);
        if (decrypted_length == -1) {
            std::cerr << "Errore durante la decriptazione del blocco." << std::endl;
            RSA_free(rsa_pubkey);
            delete[] decrypted_block;
            return "";
        }

        // Aggiungi il blocco decriptato al messaggio decriptato completo
        decrypted_message.append(reinterpret_cast<char*>(decrypted_block), decrypted_length);

        // Dealloca la memoria del blocco decriptato
        delete[] decrypted_block;

        // Passa al prossimo blocco
        offset += max_length;
    }

    // Libera la memoria della chiave RSA
    RSA_free(rsa_pubkey);

    return decrypted_message;
}

std::string encrypt_public_key_RSA_block(const std::string& message, const char* public_key_path) {
    RSA* rsa_pubkey = nullptr;
    FILE* fp = fopen(public_key_path, "r");
    rsa_pubkey = PEM_read_RSA_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!rsa_pubkey) {
        std::cerr << "Errore durante la lettura della chiave pubblica RSA." << std::endl;
        return "";
    }

    // Ottieni la dimensione massima dei blocchi crittografici
    int max_length = RSA_size(rsa_pubkey);

    std::string encrypted_message;

    // Cripta il messaggio a blocchi
    int offset = 0;
    while (offset < message.size()) {
        // Cripta il blocco corrente del messaggio
        unsigned char* encrypted_block = new unsigned char[max_length];
        int encrypted_length = RSA_public_encrypt(std::min(max_length, static_cast<int>(message.size() - offset)),
                                                  reinterpret_cast<const unsigned char*>(message.data() + offset),
                                                  encrypted_block, rsa_pubkey, RSA_PKCS1_PADDING);
        if (encrypted_length == -1) {
            std::cerr << "Errore durante la criptazione del blocco." << std::endl;
            RSA_free(rsa_pubkey);
            delete[] encrypted_block;
            return "";
        }

        // Aggiungi il blocco criptato al messaggio criptato completo
        encrypted_message.append(reinterpret_cast<char*>(encrypted_block), encrypted_length);

        // Dealloca la memoria del blocco criptato
        delete[] encrypted_block;

        // Passa al prossimo blocco
        offset += max_length;
    }

    // Libera la memoria della chiave RSA
    RSA_free(rsa_pubkey);

    return encrypted_message;
}

std::string bytesToHex(const std::vector<unsigned char>& bytes) {
    std::stringstream stream;
    for (unsigned char byte : bytes) {
        stream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return stream.str();
}

// Converto da esadecimale in byte
std::vector<unsigned char> hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoul(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

//Hashing with SHA-256
std::string sha256(std::string& input) {
    
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
std::string sha256(std::string&& input) {
    
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

//get timestamp in unix time
std::string get_current_timestamp(){

    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();

    // Converti il tempo corrente in un intero (tempo Unix)
    int unix_time = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

    // Converti il tempo Unix in una stringa
    std::string unix_time_str = std::to_string(unix_time);

    // Stampa il tempo Unix come stringa
    //std::cout << "Tempo Unix come stringa: " << unix_time_str << std::endl;

    return unix_time_str;

}

//check timestamp
int isRecentTimestamp(const std::string& current_time_str, const std::string& other_timestamp_str) {
    return (std::stoi(current_time_str)-std::stoi(other_timestamp_str));
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
        std::cout << "Impossibile aprire il file dei parametri DH!." << std::endl;
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

// Funzione per convertire BIGNUM to string
std::string bignumToString(const BIGNUM* bn) {
    if (bn == nullptr) {
        return ""; // Handle the case where BIGNUM pointer is null
    }
    
    char* hexString = BN_bn2hex(bn);
    if (hexString == nullptr) {
        return ""; // Handle the case where conversion fails
    }

    std::string result(hexString);
    OPENSSL_free(hexString); // Free the memory allocated by BN_bn2hex
    return result;
}

// Funzione che converte una stringa in un BIGNUM
BIGNUM* stringToBignum(const std::string& str) {
    BIGNUM* bn = BN_new();
    if (bn == nullptr) {
        return nullptr; // Handle the case where BN_new fails
    }

    if (BN_hex2bn(&bn, str.c_str()) == 0) {
        BN_free(bn);
        return nullptr; // Handle the case where conversion fails
    }

    return bn;
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

char* get_username (char** argv){
    return (char*)argv[1];
}

std::string get_key_path_private(std::string nome_utente){
    std::string risultato = nome_utente.append("_private_key.pem");
    return risultato;
}
std::string get_key_path_public(std::string nome_utente){
    std::string risultato = nome_utente.append("_public_key.pem");
    return risultato;
}

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
int string_to_int(std::string stringa){
    return std::stoi(stringa);
}