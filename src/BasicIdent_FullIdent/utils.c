#ifndef UTILS_C
#define UTILS_C
#include "utils.h"


void sha_fun(char target_string[], char* sha_result)
{

   SHA1Context sha;
   int i;
   unsigned int g;
   SHA1Reset(&sha);
   SHA1Input(&sha, (const unsigned char *) target_string,
             strlen(target_string));

   if (!SHA1Result(&sha))
   {
     fprintf(stderr, "ERROR-- could not compute message digest\n");
   }else{
      printf("\t");
      for (i = 0; i < 5; i++)
      {
         g = sha.Message_Digest[i];

      }

       sprintf(sha_result,
                "%08X%08X%08X%08X%08X", sha.Message_Digest[0], sha.Message_Digest[1], sha.Message_Digest[2], sha.Message_Digest[3], sha.Message_Digest[4]);

    }

}

//Hex string to in
int htoi(char a)
{
   int i;
   if (a >= 'A' && a <= 'F')
   {
      i = a - 'A' + 10;
   }else{
      i = a - '0';
   }

    return i;

}

void xor_operation(char a, char b, char* xor_result)
{

   int i;
   int j;
   int z;
   char result[10];

   i = htoi(a);
   j = htoi(b);
   z = i ^ j;
   sprintf(result, "%X", z);
   strcat(xor_result, result);

}

#endif // UTILS_C
