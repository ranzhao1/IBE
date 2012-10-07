/*
 Boneh-Franklin Identity-Based Encryption from the Weil Pairing
 Author: Ran Zhao
 Created on: Oct 4th, 2012
 This file is the implementation of BasicIdent scheme of the IBE system.(Chapter 4.2)
 This code needs GMP and PBC library.
 
 Flow Chart:
 (1)Setup:Take secruity parameter K(QBITS,RBITS),return the system parameter ans master
 key of the PKG.The system parameters include a description of a finite message space M,
 and a dscription of a finite ciphertext space C. The system parameters will be publicly
 known,while the master-key will be known only to the PKG.
 (2)Extract:The receiver extracts the corresponding private key from the PKG.
 (3)Encrypt:The sender will generate a ciphertext based on the receiver ID.
 (4)Decrypt:The receiver will use his private key to get the message digest.

 Detail:
 1.H1 function---Element build-in function(element_from_hash)
 2.H2 function---SHA1 function generate 160 bit long number
 3.H3 function---Concatenate the sigma and message digest, and
 then put it into build-in function element_random. The random number will between 0 and q.
 4.H4 function---Input a 160 bit long number and run SHA1 function to generate another 160 bit long number.
 5.As I use SHA1 function as H2 function, thus the n is automatically set as 160.
 */

#include <pbc.h>
#include <pbc_test.h>
#include <gmp.h>
#include <stdio.h>
#include <string.h>
#include "sha1.h"
#include <stdlib.h>

#define SIZE 100
#define RBITS 160
#define QBITS 512

void sha_fun(char target_string[], char* sha_result) {
    
	SHA1Context sha;
	int i;
	unsigned int g;
	SHA1Reset(&sha);
	SHA1Input(&sha, (const unsigned char *) target_string,
              strlen(target_string));
    
	if (!SHA1Result(&sha)) {
		fprintf(stderr, "ERROR-- could not compute message digest\n");
	} else {
		printf("\t");
		for (i = 0; i < 5; i++) {
			g = sha.Message_Digest[i];
            
		}
        
		sprintf(sha_result,
				"%08X%08X%08X%08X%08X", sha.Message_Digest[0], sha.Message_Digest[1], sha.Message_Digest[2], sha.Message_Digest[3], sha.Message_Digest[4]);
        
	}
    
}

//Hex String to int
int htoi(char a, int i) {
	if (a >= 'A' && a <= 'F') {
		i = a - 'A' + 10;
	} else {
		i = a - '0';
	}
	return i;
}

void xor_operation(char a, char b, char* xor_result) {
    
	int i;
	int j;
	int z;
	char result[10];
    
	i = htoi(a, i);
	j = htoi(b, j);
	z = i ^ j;
	sprintf(result, "%X", z);
	strcat(xor_result, result);
    
}

void rand_n(char* sigma) {
	int i;
	int unit;
	char tempr[10];
    memset(sigma, 0, sizeof(char)*SIZE);//Clear the memory of sigma
    
	for (i = 0; i < 40; i++) {
		unit = rand() % 16;
		sprintf(tempr, "%X", unit);
		strcat(sigma, tempr);
        
	}
    
}

int main(int argc, char **argv) {
    
	int i;
    char ID[SIZE];
    char message[SIZE];//User message
	char shamessage[SIZE]; //The input message digest(sha1 result)
	char shagid[SIZE]; //Sender H2 function result
	char shagid_receiver[SIZE]; //Receiver H2 function result
	char V[SIZE];
	char W[SIZE];
    memset(V, 0, sizeof(char)*SIZE);//Clear the memory of V
    memset(W, 0, sizeof(char)*SIZE);//Clear the memory of W
	char sigma_receiver[SIZE]; //Receiver compute the sigma
	char shamessage_receiver[SIZE]; //Receiver compute the message
    
	char sgid[SIZE]; //Sender gid string representation
	char sgid_receiver[SIZE]; //Receiver calculated gid string representation
	char sigma[SIZE]; //Sender generate the sigma
	char msigma[2*SIZE]; //Sender concatenate the sigma and message digest
	char msigma_receiver[2*SIZE]; //Receiver concatenate the sigma and message digest
	char ssigma[SIZE]; //It is the result of H4(sigma)
	char ssigma_receiver[SIZE]; //It is the result of H4(sigma_receiver)
    
	pairing_t pairing;   //The pair of bilinear map
	pbc_param_t par;   //Parameter to generate the pairing
    
	element_t P, Ppub, s, U, U_receiver, Qid, Sid, r, r_receiver, S, gid, rgid;
	mpz_t Gid, messagehash, gidhash;
	mpz_init(Gid);
	mpz_init(messagehash);
	mpz_init(gidhash);
    
	pbc_param_init_a_gen(par, RBITS, QBITS);  //Initial the parameter for the pairing
	pairing_init_pbc_param(pairing, par);   //Initial the pairing
    
	if (!pairing_is_symmetric(pairing))
		pbc_die("pairing must be symmetric");
    
    printf("Plase enter the message to encrypt:");
    scanf("%[ a-zA-Z0-9+*-!.,&*@{}$#]",message);
    getchar();
    printf("The original message=%s",message);

     
	//Get the hash of the message
	sha_fun(message, shamessage);
    
	element_init_G1(P, pairing);
	element_init_G1(Ppub, pairing);
	element_init_G1(Qid, pairing);
	element_init_G1(Sid, pairing);
	element_init_G1(U, pairing);
	element_init_G1(U_receiver, pairing);
	element_init_Zr(r, pairing);
	element_init_Zr(r_receiver, pairing);
	element_init_Zr(s, pairing);
	element_init_GT(gid, pairing);
	element_init_GT(rgid, pairing);
    
	printf("\n############SETUP############\n");
	element_random(P);
	element_random(s);
	element_mul_zn(Ppub, P, s);
	printf("System parameters have been set!\n");
	element_printf("P = %B\n", P);
	element_printf("Ppub = %B\n", Ppub);
    
	printf("###########EXTRACT###########\n");
    printf("Plase enter your ID:");
    scanf("%[ a-zA-Z0-9+*-!.,&*@{}$#]",ID);
    element_from_hash(Qid, ID, strlen(ID)); //Compute user public key
	element_mul_zn(Sid, Qid, s); //Compute user private key
    printf("\nID=%s",ID);
	element_printf("Public key Qid = %B\n", Qid);
	element_printf("Private key Sid = %B\n", Sid);
    
	printf("##########ENCRPTION##########\n");
	rand_n(sigma); //Sender generate a sigma
  
	strcpy(msigma, sigma);
	strcat(msigma, shamessage);
	element_from_hash(r, msigma, strlen(msigma));
	element_mul_zn(U, P, r);
	element_printf("U = %B", U);
	element_pairing(gid, Qid, Ppub);
	element_pow_zn(gid, gid, r);
	element_snprint(sgid, SIZE, gid);
	sha_fun(sgid, shagid); //H2(gid^r)
	sha_fun(sigma, ssigma); //H4(SIGMA)
    
	//Do the XOR operation to the sigma and shagid digest
	for (i = 0; i < 40; i++) {
		xor_operation(sigma[i], shagid[i], V);
	}
	//Do the XOR operation to the ssigma and message digest
	for (i = 0; i < 40; i++) {
		xor_operation(shamessage[i], ssigma[i], W);
	}
    
 
	printf("\nV=%s", V);
	printf("\nW=%s\n", W);
	printf("Send (U,V,W) to the receiver!");
    
	printf("\n##########DECRYPTION##########");
	element_pairing(rgid, Sid, U);
	element_snprint(sgid_receiver, SIZE, rgid);
    
	sha_fun(sgid_receiver, shagid_receiver); //Generate H2(e(dID,U));
    
	//XOR V and H2(e(dID,U))=sigma_receiver
	for (i = 0; i < 40; i++) {
		xor_operation(V[i], shagid_receiver[i], sigma_receiver);
	}
    
	sha_fun(sigma_receiver, ssigma_receiver);
    
	//XOR W andH4(sigma)
	for (i = 0; i < 40; i++) {
		xor_operation(W[i], ssigma_receiver[i], shamessage_receiver);
	}
    
	strcpy(msigma_receiver, sigma_receiver);
	strcat(msigma_receiver, shamessage_receiver);
	element_from_hash(r_receiver, msigma_receiver, strlen(msigma_receiver));
	element_mul_zn(U_receiver, P, r_receiver);
    
	if (element_cmp(U, U_receiver) == 0) {
		element_printf("\nU=%B", U);
		element_printf("\nU_receiver=%B", U_receiver);
		printf("\nYeah!The message is decrpted!");
		printf("\nThe Message Disgest=%s\n", shamessage_receiver);
	}
    
	else {
        element_printf("\nU=%B", U);
		element_printf("\nU_receiver=%B", U_receiver);
		printf("\nOops!The ciphertext can not be accepted!\n");
	}
    
	element_clear(P);
	element_clear(Ppub);
	element_clear(Qid);
	element_clear(Sid);
	element_clear(U);
	element_clear(r);
	element_clear(s);
	pairing_clear(pairing);
    
	return 0;
}

