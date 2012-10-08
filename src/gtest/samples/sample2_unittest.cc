

#include <limits.h>
#include "bf_4_2.h"
#include "gtest/gtest.h"
#include <string.h>

#define SIZE 100
#define Rbits 160
#define Qbits 512
#define ID "ran.zhao@yale.edu"

//Test htoi function
TEST(htoiTest,single1){
    char a='A';
    int b= htoi(a);
    EXPECT_EQ(10,b);
}

TEST(htoiTest,single2){
    char a='3';
    int b= htoi(a);
    EXPECT_EQ(3,b);
}
//Test xor_operation function
TEST(xor_operationTest, single1) {
    char a[]="F1Fe";
    char b[]="1111";
    char good[5];
    memset(good,0,sizeof(char)*5);
    xor_operation(a[0],b[0],good);
    EXPECT_STREQ("E",good);
}

TEST(xor_operation, single2) {
    char a[]="31Fe";
    char b[]="1111";
    char good[5];
    memset(good,0,sizeof(char)*5);
    xor_operation(a[0],b[0],good);
    EXPECT_STREQ("2",good);
}

TEST(xor_operation,more1){
    char a[]="2A3B";
    char b[]="4C5D";
    char good[5];
    int i;
    memset(good,0,sizeof(char)*5);
    for(i=0;i<4;i++){
        xor_operation(a[i],b[i],good);
    }
    EXPECT_STREQ("6666",good);
    
}

TEST(xor_operation,more2){
    
    char a[]="6EF1";
    char b[]="789E";
    char good[5];
    int i;
    memset(good,0,sizeof(char)*5);
    for(i=0;i<4;i++){
        xor_operation(a[i],b[i],good);
    }
    EXPECT_STREQ("166F",good);
    
}

//Test sha_fun function
TEST(shaTest,length){
    char target_string[]="I love coding!";
    char sha_result[SIZE];
    sha_fun(target_string,sha_result);
    EXPECT_EQ(40,strlen(sha_result));
}


//Test Combination:Setup,GetPrivateKey,GetPublicKey,Encryption,Decryption
TEST(combineTest,combination){

	char shamessage[SIZE]; //The input message digest(sha1 result)
    char V[SIZE];
	char W[SIZE];
    memset(V, 0, sizeof(char)*SIZE);//Clear the memory of V
    memset(W, 0, sizeof(char)*SIZE);//Clear the memory of W
    char shamessage_receiver[SIZE]; //Receiver compute the message
    
    pairing_t pairing;   //The pair of bilinear map
	element_t P, Ppub, s, U, U_receiver, Qid, Sid;
	mpz_t messagehash;
	mpz_init(messagehash);
    
   	SetupSys(Rbits, Qbits, P, Ppub, pairing, s);
 
    element_init_G1(Qid, pairing);
	element_init_G1(Sid, pairing);
    GetPrivateKey(ID,pairing,s,Sid);
    GetPublicKey(ID,pairing,Qid);
    //Get the hash of the message
	sha_fun("I love doing research!", shamessage);
    
    element_init_G1(U, pairing);
    Encryption(shamessage,ID,P,Ppub,U,V,W,pairing);

    element_init_G1(U_receiver, pairing);
    Decryption(Sid,pairing,P,U,V,W,U_receiver,shamessage_receiver);
    EXPECT_EQ(0,element_cmp(U, U_receiver));
    element_clear(P);
	element_clear(Ppub);
	element_clear(Qid);
	element_clear(Sid);
	element_clear(U);
	element_clear(s);
	pairing_clear(pairing);


    
    
    
}













