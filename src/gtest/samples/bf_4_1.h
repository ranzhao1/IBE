
#ifndef _BF_4_1_H_
#define _BF_4_1_H_

#include <pbc.h>
#include <gmp.h>
#include <stdio.h>
#include <string.h>
#include "sha1.h"
#include <stdlib.h>

void sha_fun(char target_string[], char* sha_result);
int htoi(char a);
void xor_operation(char a, char b, char* xor_result) ;
void GetPrivateKey(char* ID, pairing_t pairing, element_t s, element_t Sid);
void GetPublicKey(char* ID, pairing_t pairing, element_t Qid);
void Encryption(char* shamessage, char* ID, element_t P, element_t Ppub,
                element_t U, char* V, pairing_t pairing);
void Decryption(element_t Sid, pairing_t pairing, element_t U, char* V,
                char* xor_result_receiver);
void SetupSys(int rbits,int qbits,element_t P,element_t Ppub,pairing_t pairing,element_t s );

#endif
