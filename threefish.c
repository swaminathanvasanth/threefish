#include <string.h>
#include <stdio.h>
#include "threefish.h"
//Calculating Left rotate
#define rotateleft(value, shift) ((value << shift) | (value >> (64 - shift)))

int rotation[8][4] = {
  { 46, 36, 19, 37 },
  { 33, 27, 14, 42 },
  { 17, 49, 36, 39 },
  { 44,  9, 54, 56 },
  { 39, 30, 34, 24 },
  { 13, 50, 10, 17 },
  { 25, 29, 39, 43 },
  {  8, 35, 56, 22 }
}; // Rotation Parameters
// initialize a cipher context. k points to a 64-byte key, t to a 16-byte tweak.
// you initialize counter mode here and possibly precompute the round keys.
void init(const unsigned char *k, const unsigned char *t, tctx *ctx)
{
  int d,s=0;
  unsigned char t2[8];
  unsigned long key[9],tweak[3],xor,knw,mix[8],kk[8],p[8],y[8],x[8],temp[8],temp_y[8];
  memcpy(key,k,64); // Copying the Key and Tweak 
  memcpy(tweak,t,16);
  memset(ctx->counter,0,64);
  /* Calculation of t2 (t2=t0 xor t1) */
  tweak[2]= tweak[0] ^ tweak[1];
  for(int keyposition=0;keyposition<8;keyposition++) 
  {
    if(keyposition==0)
      xor=key[keyposition];
    else
      xor=key[keyposition]^xor;
  }      
  knw=0x5555555555555555LL^xor;

  key[8] = knw;
  // Loop for 19 Sub Keys.Calculation of Keys 
  for(s=0;s<19;s++)
  {
    for(int i=0;i<8;i++)
    {
      if(i ==0 || i ==1 || i ==2 || i ==3 || i ==4)
        ctx->keyschedule[s][i] = key[(s+i)%9]; 
      else if(i==5)
        ctx->keyschedule[s][i] = ((key[(s+i)%9])+tweak[s%3]);
      else if(i==6)
        ctx->keyschedule[s][i] = ((key[(s+i)%9])+tweak[(s+1)%3] );     
      else
        ctx->keyschedule[s][i] = ((key[(s+i)%9])+s);
    }
  }
  ctx->avail_cntr_bytes = 0;
}

// using context ctx, encrypt len bytes of plaintext p and store the result in b.
void threefish(unsigned long *b, unsigned long *p, int len, tctx *ctx) {
  unsigned long key[9],tweak[3],xor,knw,mix[8],kk[8],y[8],x[8],temp[8],temp_y[8];
  int d,s=0,flag=0;
  //MIX Function Calculation
  for(int j=0;j<8;j++)
  {
     x[j]=p[j]+ctx->keyschedule[0][j];
  }

  //Calculation of Subkey 
  for(d=0;d<72;d++)  
  {
    x[0]=(x[0]+x[1]);
    temp_y[0]=rotateleft(x[1],rotation[d%8][0]);
    x[1]=temp_y[0] ^ x[0];

    x[2]=(x[2]+x[3]);
    temp_y[2]=rotateleft(x[3],rotation[d%8][1]);
    x[3]=temp_y[2] ^ x[2];

    x[4]=(x[4]+x[5]);
    temp_y[4]=rotateleft(x[5],rotation[d%8][2]);
    x[5]=temp_y[4] ^ x[4];

    x[6]=(x[6]+x[7]);
    temp_y[6]=rotateleft(x[7],rotation[d%8][3]);
    x[7]=temp_y[6] ^ x[6];

   //Permutation. Copying output of each round to a temp variable for permutation.
      temp[0]=x[0];
      temp[1]=x[1];
      temp[2]=x[2];
      temp[3]=x[3];
      temp[4]=x[4];
      temp[5]=x[5];
      temp[6]=x[6];
      temp[7]=x[7];
   //Permutation is done here
    uint64_t tmp0=x[0];
    uint64_t tmp3=x[3];
    x[0]=x[2];
    x[1]=x[1];
    x[2]=x[4];
    x[3]=x[7];
    x[4]=x[6];
    x[5]=x[5];
    x[6]=tmp0;
    x[7]=tmp3;

    if((d+1)%4==0) //Checking the round number to add the subkey every 4th round
    {
      for(int i=0;i<8;i++)
        x[i]=x[i]+ctx->keyschedule[(d+1)/4][i]; //add new sub key to the obtained solution 
    }
  }
  memcpy(b,x,64);
}

void crypt(unsigned char *b, unsigned char *p, int len, tctx *ctx) 
{
//Counter Mode
  int k=0;
  int kkkk=0;
  int numofcalls;
  int t;
  int m=0;
  if(ctx->avail_cntr_bytes!=0) //Checking for the available counter bytes left from the previous XOR operations
  {
    if(len < ctx->avail_cntr_bytes) // If the Plain Text size is more than the available counter bytes XOR the Plain Text with Counter Bytes and save the remaining.
    { 
      for(k=0;k<len;k++) 
      {
        b[k] = ctx->stored_avail_cntr_bytes[k] ^ p[k];  
      } 
       ctx->avail_cntr_bytes = ctx->avail_cntr_bytes - len;  
       memmove(&ctx->stored_avail_cntr_bytes[0], &ctx->stored_avail_cntr_bytes[len] ,ctx->avail_cntr_bytes);// Move the remaining bytes after computing it
       return;
    }  
    else if(len > ctx->avail_cntr_bytes) // If the Plain Text size is less than the available counter bytes XOR the Plain Text with Counter Bytes and generate keys
   { 
      for(kkkk=0;kkkk<ctx->avail_cntr_bytes;kkkk++) 
      {
         b[kkkk] = ctx->stored_avail_cntr_bytes[kkkk] ^ p[kkkk]; 
      } 
      len = len - ctx->avail_cntr_bytes;
    }
    else // If Plaintext size is equal to available counter bytes, XOR it with the Plain Text
    {
      for(k=0;k<ctx->avail_cntr_bytes;k++) 
      {
         b[k] = ctx->stored_avail_cntr_bytes[k] ^ p[k]; 
      }
      ctx->avail_cntr_bytes=0;
      return;
    }
  }
  numofcalls = len/64; //Calculating num of calls to generate Keys.  
  if( len % 64 != 0 ) //If length of Plain Text is greater than 64 bytes increment the number of threefish function calls for key generations
  {
    numofcalls++; 
  } 
  else
  {
    numofcalls=1; //If length of Plain Text is less than 64 bytes initialise numof calls to 1.
  }
  unsigned long store_key[(numofcalls*8)]; 
  unsigned char store_key_char[(numofcalls*64)]; 
  for(int k=0;k<numofcalls;k++) // Calling the Threefish function for generating the keys for the respective number of times
  {
    threefish(&store_key[k*8],ctx->counter,64,ctx); //Computing the threefish function for required number of calls
    ctx->counter[0]++;
  } 
  memcpy(store_key_char,store_key,(numofcalls*64)); 
   int i;
  for(i=0;i<len;i++,kkkk++) 
  {
    b[kkkk] = store_key_char[i] ^ p[kkkk]; // XOR the Plaintext with the available Keys and storing it in the array.
  } 
  ctx->avail_cntr_bytes = ((numofcalls*64)-len); // Available number of bytes in the key after performing the XOR operation.
  int num = (numofcalls*64); 
  for(t=0;t<num-len+1;t++,i++)  
  {
    ctx->stored_avail_cntr_bytes[t] = store_key_char[i]; //Moving the remaining available bytes    
  } 
}
