####################################README###########################################

Overview
In order to compile the code, you need to install the PBC library and GMP library.
PBC library is a C library providing low-level routines for pairing-based cyptosystems.
I use SHA1 function as my hash function, which generate 160-bit long numbers. 

Compile Code
After you install both PBC library and GMP library, you could compile the code by following
instruction: 

gcc bf_4_1.c sha1.c  -o test -I /usr/local/include/ -L /usr/local/lib/ -Wl,-rpath 
/usr/local/lib -l pbc -l gmp 

gcc bf_4_2.c sha1.c  -o test1 -I /usr/local/include/ -L /usr/local/lib/ -Wl,-rpath 
/usr/local/lib -l pbc -l gmp 

Sample Review
(1)Setup:Take secruity parameter K(QBITS,RBITS),return the system parameter ans master 
key of the PKG.The system parameters include a description of a finite message space M,
and a dscription of a finite ciphertext space C. The system parameters will be publicly
known,while the master-key will be known only to the PKG.
(2)Extract:The receiver extracts the corresponding private key from the PKG.
(3)Encrypt:The sender will generate a ciphertext based on the receiver ID.
(4)Decrypt:The receiver will use his private key to get the message digest.

-------------------------------------------------------------------------------------
Ran Zhao <ran.zhao@yale.edu>