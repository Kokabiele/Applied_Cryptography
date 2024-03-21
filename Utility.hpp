#ifndef _UTILITY_HPP_
#define _UTILITY_HPP_
#include <string>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <vector>
#include <nlohmann/json.hpp>
using namespace nlohmann;

//funzioni per la gestione dell'hash
std::string sha256(std::string& input);
bool compareHash(const std::string& inputHash, const std::string& knownHash);

//funzioni per la gestione del timestamp
std::string get_current_timestamp();
int isRecentTimestamp(const std::string& current_time_str, const std::string& other_timestamp_str);

//funzioni per la gestione delle nonce
std::string generateNonce();
std::string incrementNonce(const std::string& nonce);
bool check_nonce (const std::string& mynonce, const std::string& received_nonce);

//funzioni per la gestione di diffie hellman
DH* generateDHFromParamsFile();
const BIGNUM* get_pub_key_DH(DH* dh_params);
const BIGNUM* readDHPublicKeyFromFile();
std::vector<unsigned char> computeSharedSecret(const BIGNUM* pub_key_peer, DH* dh_params);
char* get_username (char** argv);

//conversioni bignum to string e viceversa
std::string bignumToString(const BIGNUM* bn);
BIGNUM* stringToBignum(const std::string& str);

//conversioni hex to byte e viceversa
std::string bytesToHex(const std::vector<unsigned char>& bytes);
std::vector<unsigned char> hexToBytes(const std::string& hex);

//funzioni per ottenere il path della posizione della chiave pubblica/privata
std::string get_key_path_private(std::string nome_utente);
std::string get_key_path_public(std::string nome_utente);

//funzioni per la crittografia asimmetrica
std::string decrypt_private_key_RSA_block(const std::string& encrypted_message, const char* private_key_path);
std::string encrypt_private_key_RSA_block(const std::string& message, const char* private_key_path);
std::string decrypt_public_key_RSA_block(const std::string& encrypted_message, const char* public_key_path);
std::string encrypt_public_key_RSA_block(const std::string& message, const char* public_key_path);

//funzioni per la crittografia simmetrica
std::string decrypt_AES_GCM(const std::vector<unsigned char>& key, const std::string& encrypted_message);
std::string encrypt_AES_GCM(const std::vector<unsigned char>& key, const std::string& plaintext);

//funzioni per lavorare sui dati json
void add_json (json& data, std::string key, std::string new_value);
void remove_json (json& data, std::string key);
std::string json_to_string (const json& data);
json string_to_json(std::string stringa);

void clear_shared_key(std::vector<unsigned char>& shared_key);
#endif
