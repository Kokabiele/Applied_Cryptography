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
#include "Utility.hpp"
using namespace std;

#define porta 9000

int main(int argc, char **argv){
    
    int sockfd, n;
    struct sockaddr_in local_addr, dest_addr;
    char sendline[1000];
    char recvline[1000];

    if (argc != 3)
    { 
        printf("write username and password!");
        return 1;
    }


	string username = argv[1];
	string password = argv[2];

	if(username.size() > 20 || password.size() > 20){
        printf("Username or password too long");
        return 2;
    }

	cout << "Username: " << username << endl;
	cout << "Password: " << password << endl;

    sockfd=socket(AF_INET,SOCK_STREAM,0);//connessione TCP
    memset( &dest_addr, 0, sizeof(dest_addr));//puliamo tutto mettendo 0
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr("127.0.0.1");//indirizzo
    dest_addr.sin_port = htons(porta);//porta
    connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(dest_addr));

    while (fgets(sendline,999,stdin) != NULL)
    {   
        if (strcmp(sendline, "quit\n") == 0) {
            string test = sendline;
            // Esci se l'utente ha scritto "quit"
            cout << "Exiting..." << endl;
            //string suca = encryptRSA(test);
            cout << "Ora cripto la parola 'quit'" << endl;
            //cout << suca << endl;
            cout << "Adesso invece la decripto" << endl;
            //cout << decryptRSA(suca) << endl;
            cout << "Adesso creo l'hash della parola quit" << endl;
            string hash_test = sha256("quit");
            cout << hash_test << endl;
            cout << "Ora invece vedo se l'hash calcolato coincide con quello che conosciamo" << endl;
            cout << compareHash(hash_test, "8577da2ea54085708b3b851bc50315a36bb740ba5135e747cfb12457b5d3060f") << endl;
            cout << "Ora mostro il timestamp" << endl;
            cout << get_current_timestamp() << endl;
            cout << "Ora genero delle nonce, ne farò tre per testarne la randomicià effettiva" << endl;
            cout << generateNonce() << endl;
            cout << generateNonce() << endl;
            string test_nonce = generateNonce();
            cout << test_nonce << endl;
            cout << "Questa ultima nonce la checkeremo applicando un ++" << endl;
            string test_nonce_p = incrementNonce(test_nonce);
            cout << "Questa è la nonce incrementata" << endl;
            cout << test_nonce_p << endl;
            cout << "Ora faccio il check se è stata incrementata correttamente" << endl;
            cout << check_nonce(test_nonce, test_nonce_p) << endl;
            cout << "vedo se la funzione per la generazione della chiave pubblica DH funziona"  << endl;
            DH* dh_params = generateDHFromParamsFile();//fino a qua ci siamo
            const BIGNUM* test_bn = get_pub_key_DH(dh_params);//straggo la chiave pubblica del client
            FILE* file = fopen("file_test_dh.txt", "w");//la scrivo in un file
            if (!file) {
                fprintf(stderr, "Errore nell'apertura del file.\n");
                return 1;
            }
            if (test_bn == NULL) {
                fprintf(file, "NULL\n");
                fclose(file);
                return 1;
            }
            BN_print_fp(file, test_bn);
            fprintf(file, "\n");

            // Chiudi il file
            fclose(file);
            std::cout << "Fino a qua funziona!" << std::endl;
            //fino a qua ho la chiave pubblica del client in file_test_DH faccio finta che quella del server si trova in 
            //file_test_DH2
            const BIGNUM* pub_key_server = readDHPublicKeyFromFile();
            vector<unsigned char> risultato = computeSharedSecret(pub_key_server, dh_params);
            std::cout << "Risultato del calcolo del segreto condiviso:" << std::endl;
            for (unsigned char byte : risultato) {
                std::cout << std::hex << (int)byte << " "; // Stampa il byte in formato esadecimale
            }
            std::cout << std::endl;
            cout << "Ora farò questo test: cripto 'quit' con la chiave privata del server e successivamente la decripto con la sua chiave pubblica" << endl;
            string cripted_suca = encrypt_private_key_RSA(test, "Server_private_key.pem");
            cout << "Ora cripto la parola 'quit'" << endl;
            cout << cripted_suca << endl;
            cout << "Adesso invece la decripto" << endl;
            string decripted_suca = decrypt_public_key_RSA(cripted_suca, "Server_public_key.pem");
            cout << decripted_suca << endl;
            cout << "Qui invece faccio un altro passaggio dove cripto con chiave pubblica e decripto con quella privata" << endl;
            cout << "Versione criptata con chiave pubblica:" << endl;
            cripted_suca = encrypt_public_key_RSA(decripted_suca, "Server_public_key.pem");
            cout << cripted_suca << endl;
            cout << "Versione decriptata con chiave privata" << endl;
            decripted_suca = decrypt_private_key_RSA(cripted_suca, "Server_private_key.pem");
            cout << decripted_suca << endl;
            break;
        }
        
        send(sockfd,sendline,strlen(sendline),0);
        n=recv(sockfd,recvline,999,0);
        recvline[n]=0;
        printf("\nReceived from server %s:%d the following message:%s\n", inet_ntoa(dest_addr.sin_addr),ntohs(dest_addr.sin_port), recvline );
    }
}