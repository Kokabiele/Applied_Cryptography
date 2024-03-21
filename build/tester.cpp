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
    std::vector<unsigned char> key(EVP_MAX_KEY_LENGTH); // Lunghezza massima della chiave
    PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt.data(), salt.size(), 1000, EVP_sha256(), key.size(), key.data());
    return key;
}
// Controllo per l'inserimento corretto della password
bool comparePasswordHash(std::string& password, const std::string& salt, const std::string& storedHash) {
    // Decodifica il sale memorizzato nel file JSON da esadecimale a vettore di byte
    //mettere l'hash della stringa password dentro calculatePasswordHash.
    std::vector<unsigned char> saltBytes;
    for (size_t i = 0; i < salt.length(); i += 2) {
        unsigned int byte;
        std::stringstream ss;
        ss << std::hex << salt.substr(i, 2);
        ss >> byte;
        saltBytes.push_back(static_cast<unsigned char>(byte));
    }

    // Calcola l'hash della password fornita utilizzando il sale
    std::vector<unsigned char> calculatedHash = calculatePasswordHash(password, saltBytes);

    // Confronta l'hash calcolato con l'hash memorizzato nel file JSON
    // std::string calculatedHashStr(calculatedHash.begin(), calculatedHash.end());
    std::string hashedPasswordString = bytesToHex(calculatedHash);
    return (hashedPasswordString == storedHash);
}

//true se c'è qualcosa, false se vuoto
bool checkEmpityFile(){
    std::ofstream fileUtentiCheck("Utenti.json", std::ios::app);
    if (fileUtentiCheck.is_open()) {
        // Aggiungi una virgola prima di aggiungere il nuovo oggetto JSON se il file non è vuoto
        if (fileUtentiCheck.tellp() != 0) {
            std::cout << "file 'Utenti.json' non vuoto" << std::endl;
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
std::vector<unsigned char> deriveKey(const std::string& password, const std::vector<unsigned char>& salt) {
    std::vector<unsigned char> key(EVP_MAX_KEY_LENGTH); // Lunghezza massima della chiave
    PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt.data(), salt.size(), 1000, EVP_sha256(), key.size(), key.data());
    return key;
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
    std::string username = "Marco";
    std::string password = "ciao";
    
    //prendo il sale che trovo all'utente corrispondente
    std::string saltString = jsonData[0]["salt"];
    std::cout << "test" << std::endl;
    // La converto in byte per poterlo inserire nel calcolo dell'hash
    std::vector<unsigned char> saltByte = hexToBytes(saltString);
    
    // Deriva la chiave dalla password con salt utilizzando PKCS5_PBKDF2_HMAC
    // std::vector<unsigned char> hashedPassword = deriveKey(password, saltByte);
    // La converto in esadecimale per farne il confronto con quello dentro il file .json
    // std::string hashedPasswordString = bytesToHex(hashedPassword);
    // controllo se la password all'interno del file json corrisponde a quella appena calcolata
    if(comparePasswordHash(password, saltString, jsonData[0]["password"])){
        std::cout << "bravo" << std::endl;
        std::cout << "Utente dentro il json" << jsonData[0]["username"] << std::endl;
        std::cout << "password dentro il json" << jsonData[0]["password"] << std::endl;
        //std::cout << "password calcolata" << hashedPasswordString << std::endl;
    }else{
        std::cout << "Non funziona" << std::endl;
        std::cout << "Utente dentro il json" << jsonData[0]["username"] << std::endl;
        std::cout << "password dentro il json" << jsonData[0]["password"] << std::endl;
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



    //aggiungo utenti al file json
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