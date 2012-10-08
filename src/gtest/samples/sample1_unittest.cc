

#include <limits.h>
#include "bf_4_1.h"
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
        char xor_result[SIZE]; //Sender XOR result---V
        char xor_result_receiver[SIZE];  //Receiver XOR result
        memset(xor_result, 0, sizeof(char)*SIZE);
        memset(xor_result_receiver, 0, sizeof(char)*SIZE);
        pairing_t pairing;   //The pair of bilinear map
        element_t P, Ppub, s, U, Qid, Sid;
        mpz_t messagehash;
        mpz_init(messagehash);
        SetupSys(Rbits,Qbits,P, Ppub, pairing, s);
        element_init_G1(Qid, pairing);
        element_init_G1(Sid, pairing);
        GetPrivateKey(ID, pairing, s, Sid);
        GetPublicKey(ID, pairing, Qid);
        sha_fun("I love coding!", shamessage);   //Get the message digest
        element_init_G1(U, pairing);
        Encryption(shamessage, "", P, Ppub, U, xor_result, pairing);
        Decryption(Sid, pairing, U, xor_result, xor_result_receiver);
        EXPECT_STREQ(xor_result_receiver,shamessage);

        
        //Free space
        element_clear(P);
        element_clear(Ppub);
        element_clear(Qid);
        element_clear(Sid);
        element_clear(U);
        element_clear(s);
        pairing_clear(pairing);
    
    
    
}





