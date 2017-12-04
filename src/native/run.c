#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include "nimiq_native.h"
#include "ed25519/fe.h"
#include "ed25519/ge.h"

#define HARD_COUNT 100
#define LIGHT_COUNT 10000000

void ed25519_public_key_derive(unsigned char *out_public_key, const unsigned char *private_key);
void ed25519_key_xy(unsigned char *s64, const unsigned char *key, const int private);
void ed25519_derive_child(unsigned char *out_private_key, const unsigned char *private_key, const unsigned char *index);

void logasuint(const unsigned char* val, const char* desc, int len){
    printf("\n%-16s = [", desc);
    len = len == 0 ? 32 : len;
    for (int i = 0; i < len; i++){
        if(i==32) printf("\n\t\t     ");
        printf("% 3d,", val[i]);
    }
    //while(*val)
    // {
    //     printf("% 3d,", *val++);
    // }
    printf(" ] \n");
}

int main() {

    fe FE;
    unsigned char* s32 = malloc(32);
    unsigned char* s64 = malloc(64);

    unsigned char NUM[32] = { 
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2
        }; 
    logasuint(NUM, "num", 0);
    fe num;
    fe_frombytes(num,NUM);


    unsigned char priv1[32] = { 
        92, 34, 248, 147, 114, 16, 19, 10, 209, 187, 197, 6, 120, 167, 192, 161, 25, 164, 131, 212, 121, 40, 195, 35, 191, 11, 170, 58, 87, 250, 84, 125
        }; 
    logasuint(priv1, "nimiq_prv_key", 0);
    
    unsigned char expriv1[64] = { 
        92, 34, 248, 147, 114, 16, 19, 10, 209, 187, 197, 6, 120, 167, 192, 161, 25, 164, 131, 212, 121, 40, 195, 35, 191, 11, 170, 58, 87, 250, 84, 125
        ,24, 12, 153, 134, 21, 99, 108, 216, 117, 170, 112, 199, 28, 250, 107, 123, 245, 112, 24, 122, 86, 216, 198, 208, 84, 230, 11, 100, 77, 19, 233, 211
        };        
    ed25519_derive_child(s64,expriv1,NUM);
    logasuint(s64, "prv_derived_m/num", 64);

    fe_frombytes(FE, priv1);
    fe privPlus;
    fe_add(privPlus, FE, num);
    fe_tobytes(s32,privPlus);
    logasuint(s32, "privPlus", 0);

    unsigned char pub_privPlus[32];
    ed25519_public_key_derive(pub_privPlus,s32);
    logasuint(pub_privPlus, "pub_privPlus", 0);    
    
    ed25519_key_xy(s64, priv1, 1);
    logasuint(s64, "nimiq_prv_xy", 64);

    fe_0(FE);
    unsigned char pub1[32];
    ed25519_public_key_derive(pub1,priv1);
    logasuint(pub1, "nimiq_pub_key", 0);
    fe_frombytes(FE, pub1);

    ed25519_key_xy(s64, pub1, 0);
    logasuint(s64, "nimiq_pub_xy", 64);

    // fe u;
    // fe pubPlus;
    // fe_mul(u,num,sqrtm1);
    // fe_add(pubPlus, FE, u);
    // fe_tobytes(s32, pubPlus);
    // logasuint(s32, "pubPlus", 0); 
    // ed25519_key_xy(s64, s32, 0);
    // logasuint(s64, "pub_pubPlus", 64); 

    // unsigned char btcjs_pub_key[33] = { 
    //        2, 62, 71, 64, 208, 186, 99, 158, 40, 150, 63, 52, 118, 21, 123, 124, 242, 251, 124, 111, 223, 66, 84, 249, 112, 153, 207, 134, 112, 181, 5, 234, 89
    //     }; 
    // logasuint(btcjs_pub_key, "target_pub_key", 0);

    free(s32);
    free(s64);

    return 0;


    long start, end;
    struct timeval timecheck;
    char* out = malloc(32);
    char* in = strdup("Test1");

    gettimeofday(&timecheck, NULL);
    start = (long)timecheck.tv_sec * 1000 + (long)timecheck.tv_usec / 1000;

    for(int i = 0; i < HARD_COUNT; ++i) {
        nimiq_hard_hash(out, in, 5, 512);
        in[0]++;
    }

    gettimeofday(&timecheck, NULL);
    end = (long)timecheck.tv_sec * 1000 + (long)timecheck.tv_usec / 1000;
    printf("Hard(512 KiB) %ldms => %ld H/s\n", end-start, (HARD_COUNT*1000)/(end-start));
    start = end;

    for(int i = 0; i < HARD_COUNT; ++i) {
        nimiq_hard_hash(out, in, 5, 1024);
        in[0]++;
    }

    gettimeofday(&timecheck, NULL);
    end = (long)timecheck.tv_sec * 1000 + (long)timecheck.tv_usec / 1000;
    printf("Hard(1024 KiB) %ldms => %ld H/s\n", end-start, (HARD_COUNT*1000)/(end-start));
    start = end;

    for(int i = 0; i < LIGHT_COUNT; ++i) {
        nimiq_light_hash(out, in, 5);
        in[0]++;
    }

    gettimeofday(&timecheck, NULL);
    end = (long)timecheck.tv_sec * 1000 + (long)timecheck.tv_usec / 1000;
    printf("Light %ldms => %ld kH/s\n", end-start, (LIGHT_COUNT)/(end-start));
    start = end;

    for(int i = 1; i < 4; ++i) {
        free(in);
        in = malloc(32);
        snprintf(in, 31, "Test1%d0000", i);
        uint32_t nonce = nimiq_hard_hash_target(out, in, strlen(in), 0x20000000u + (0xffff >> i), 0, (uint32_t)-1, 512);
    
        gettimeofday(&timecheck, NULL);
        end = (long)timecheck.tv_sec * 1000 + (long)timecheck.tv_usec / 1000;
        if (end-start == 0) end++;
        printf("Hard(%d) %ldms => (real: %ld H/s, observed: %ld H/s)\n", i, end-start, (1000 * nonce)/(end-start), (1000 << (i+8))/(end-start));
        start = end;
    }

    free(in);
    free(out);
    return 0;
}
