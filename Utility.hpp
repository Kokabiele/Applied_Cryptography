#ifndef _UTILITY_HPP_
#define _UTILITY_HPP_
#include <string>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <vector>
// std::string encrypt_public_key_RSA(const std::string& message, const char *public_key_path);
// std::string encrypt_private_key_RSA(const std::string& message, const char* private_key_path);
// std::string decrypt_public_key_RSA(const std::string& encrypted_message, const char* public_key_path);
// std::string decrypt_private_key_RSA(const std::string& encrypted_message, const char *private_key_path);
std::string sha256(const std::string& input);
bool compareHash(const std::string& inputHash, const std::string& knownHash);
std::string get_current_timestamp();
int isRecentTimestamp(const std::string& current_time_str, const std::string& other_timestamp_str);
std::string generateNonce();
std::string incrementNonce(const std::string& nonce);
bool check_nonce (const std::string& mynonce, const std::string& received_nonce);
DH* generateDHFromParamsFile();
const BIGNUM* get_pub_key_DH(DH* dh_params);
const BIGNUM* readDHPublicKeyFromFile();
std::vector<unsigned char> computeSharedSecret(const BIGNUM* pub_key_peer, DH* dh_params);
char* get_username (char** argv);
std::string bignumToString(const BIGNUM* bn);
BIGNUM* stringToBignum(const std::string& str);
std::string bytesToHex(const std::vector<unsigned char>& bytes);
std::vector<unsigned char> hexToBytes(const std::string& hex);
std::string get_key_path_private(std::string nome_utente);

std::string get_key_path_public(std::string nome_utente);

std::string decrypt_private_key_RSA_block(const std::string& encrypted_message, const char* private_key_path);
std::string encrypt_private_key_RSA_block(const std::string& message, const char* private_key_path);
std::string decrypt_public_key_RSA_block(const std::string& encrypted_message, const char* public_key_path);
std::string decrypt_AES_GCM(const std::vector<unsigned char>& key, const std::string& encrypted_message);
std::string encrypt_AES_GCM(const std::vector<unsigned char>& key, const std::string& plaintext);
#endif
