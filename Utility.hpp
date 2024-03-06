#ifndef _UTILITY_HPP_
#define _UTILITY_HPP_
#include <string>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <vector>
std::string encryptRSA(const std::string& message);
std::string decryptRSA(const std::string& encrypted_message);
std::string sha256(const std::string& input);
bool compareHash(const std::string& inputHash, const std::string& knownHash);
std::string get_current_timestamp();
std::string generateNonce();
std::string incrementNonce(const std::string& nonce);
bool check_nonce (const std::string& mynonce, const std::string& received_nonce);
DH* generateDHFromParamsFile();
const BIGNUM* get_pub_key_DH(DH* dh_params);
const BIGNUM* readDHPublicKeyFromFile();
std::vector<unsigned char> computeSharedSecret(const BIGNUM* pub_key_peer, DH* dh_params);
#endif
