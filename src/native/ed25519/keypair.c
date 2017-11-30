#include "ed25519.h"
#include "sha512.h"
#include "ge.h"

void ed25519_public_key_derive(unsigned char *out_public_key, const unsigned char *private_key) {
    unsigned char az[64];
    ge_p3 A;

    // decompress the 32 byte private key into 64 byte
    sha512(private_key,32,az);

    az[0] &= 248;
    az[31] &= 63;
    az[31] |= 64;

    ge_scalarmult_base(&A,az);
    ge_p3_tobytes(out_public_key, &A);
}

void ed25519_public_key_x(unsigned char *s, const unsigned char *public_key) {
    ge_p3 A;
    fe recip;
    fe x;
    //fe y;
    
    if (ge_frombytes_negate_vartime(&A, public_key) != 0) {
        return;
    }
    
    //fe_tobytes(s, A.X);
    //same as ge_p3_tobytes() without the Z & Y 
    //fe_invert(recip, A.Z);
    fe_mul(x, A.X, recip);
    //fe_mul(y, A.Y, recip);
    fe_tobytes(s, x);
    s[31] ^= fe_isnegative(x) << 7;
}