#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// Converto in esadecimale per supportare la libreria json
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
// Calcolo l'hash della password insieme al sale
std::vector<unsigned char> calculatePasswordHash(const std::string& password, const std::vector<unsigned char>& salt) {
    std::vector<unsigned char> hash_password(EVP_MAX_KEY_LENGTH); // Lunghezza massima della chiave
    PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt.data(), salt.size(), 1000, EVP_sha256(), hash_password.size(), hash_password.data());
    return hash_password;
}
// Controllo per l'inserimento corretto della password
bool comparePasswordHash(const std::string& password, const std::string& salt, const std::string& storedHash) {
    // Decodifica il sale memorizzato nel file JSON da esadecimale a vettore di byte
    std::vector<unsigned char> saltBytes = hexToBytes(salt);

    // Calcola l'hash della password fornita utilizzando il sale
    std::vector<unsigned char> calculatedHash = calculatePasswordHash(password, saltBytes);

    // Confronta l'hash calcolato con l'hash memorizzato nel file JSON
    // std::string calculatedHashStr(calculatedHash.begin(), calculatedHash.end());
    std::string hashedPasswordString = bytesToHex(calculatedHash);
    return (hashedPasswordString == storedHash);
}
// Checker se l'utente che vuole collegarsi esiste -1 se non presente altrimenti restituisce la posizione
int check_user(const json& data, const std::string username){
    for(int i = 0; i < data.size(); i++){
        if(data[i]["username"] == username)
        {
            std::cout << "Utente trovato dentro il json " << data[i]["username"] << " == " << username << std::endl;
            return i;
        }
    }
    return -1;
}
int main() {
    
    //apro il file .json
    std::ifstream file("Utenti.json");
    if (!file.is_open()) {
        std::cerr << "Impossibile aprire il file JSON." << std::endl;
        return 1;
    }
    json jsonData;
    file >> jsonData;
    
    file.close();
    //prendo il nome utente ricevuto e la password
    std::string username = "ciao2";
    std::string password = "suca";
    
    //prendo il sale che trovo all'utente corrispondente
    std::string saltString = jsonData[2]["salt"];
    
    // La converto in byte per poterlo inserire nel calcolo dell'hash
    std::vector<unsigned char> saltByte = hexToBytes(saltString);
    int checker = check_user(jsonData, username);
    if(checker != -1){
        std::cout << "bravo, l'utente si trova nella posizione: " << checker <<std::endl;
    }else{
        std::cout << "Non funziona" << std::endl;
    }
    // controllo se la password all'interno del file json corrisponde a quella appena calcolata
    if(comparePasswordHash(password, saltString, jsonData[2]["password"])){
        std::cout << "bravo" << std::endl;
        std::cout << "Utente dentro il json" << jsonData[2]["username"] << std::endl;
        std::cout << "password dentro il json" << jsonData[2]["password"] << std::endl;
        //std::cout << "password calcolata" << hashedPasswordString << std::endl;
    }else{
        std::cout << "Non funziona" << std::endl;
        std::cout << "Utente dentro il json" << jsonData[2]["username"] << std::endl;
        std::cout << "password dentro il json" << jsonData[2]["password"] << std::endl;
        //std::cout << "password calcolata" << hashedPasswordString << std::endl;
    }
    /*if(jsonData[2]["password"] == hashedPasswordString){
        //troviamo la corrispondenza
        std::cout << "bravo" << std::endl;
        std::cout << "Utente dentro il json" << jsonData[2]["username"] << std::endl;
        std::cout << "password dentro il json" << jsonData[2]["password"] << std::endl;
        std::cout << "password calcolata" << hashedPasswordString << std::endl;

    }else{
        // non troviamo la corrispondenza
        std::cout << "Non funziona" << std::endl;
        std::cout << "Utente dentro il json" << jsonData[2]["username"] << std::endl;
        std::cout << "password dentro il json" << jsonData[2]["password"] << std::endl;
        std::cout << "password calcolata" << hashedPasswordString << std::endl;
    }*/

    // std::cout << jsonData.dump(4) << std::endl;
    // std::cout << "Il nome utente è: " << jsonData[1]["username"] << std::endl;
    // std::cout << "Ci sono tot: oggetti " << jsonData.size() << std::endl;
    //std::string nomeUtentePrimo = jsonData[1]["username"];
    // Confronta l'hash della password fornita con l'hash memorizzato nel file JSON
    
    return 0;
}




    /*std::string nomeUtente, password;
    
    // Leggi il nome utente e la password inseriti dall'utente
    std::cout << "Inserisci il nome utente: ";
    std::cin >> nomeUtente;
    std::cout << "Inserisci la password: ";
    std::cin >> password;
    
    // Genera un salt casuale per l'utente
    std::vector<unsigned char> salt = generateSalt();
    // La converto in esadecimale per essere supportato dal json
    std::string saltString = bytesToHex(salt);
    
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
    } else {
        std::cerr << "Errore nell'apertura del file 'Utenti.json'" << std::endl;
    }*/