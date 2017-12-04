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

void ed25519_derive_child(unsigned char *extended_out, const unsigned char *extended_in, const unsigned char *index) {
    unsigned char az[64];
    ge_p3 A;
    unsigned char pubk[32];

    // decompress the 32 byte private key into 64 byte
    sha512(extended_in,32,az);

    az[0] &= 248;
    az[31] &= 63;
    az[31] |= 64;

    ge_scalarmult_base(&A,az);
    ge_p3_tobytes(pubk, &A);
    

    ge_p2 R;
    ge_double_scalarmult_vartime(&R, extended_in+32, &A, index);

    //----------------------------------------
    fe a,b,c;
    fe_frombytes(a,extended_in+32);
    fe_frombytes(b,index);
    fe_add(c,a,b);

    ge_cached gc;
    ge_p3_to_cached(&gc, &A);

    unsigned char d[32];
    fe_tobytes(d,c);

    sha512(d,64,extended_out);
}

void ed25519_key_xy(unsigned char *xy, const unsigned char *key, const int private) {
    unsigned char sy[32];
    unsigned char az[64];
    ge_p3 A;
    int32_t *X;
    int32_t *Y;

    if(private == 0){
        if (ge_frombytes_negate_vartime(&A, key) != 0) {
            return;
        }
        X = A.X;
        Y = A.Y;
    } else {
        // decompress the 32 byte private key into 64 byte
        sha512(key,32,az);

        az[0] &= 248;
        az[31] &= 63;
        az[31] |= 64;

        ge_scalarmult_base(&A,az);

        X = A.X;
        Y = A.Y;
    }

    fe_tobytes(xy, X);
    fe_tobytes(sy, Y);
    for(int i = 0; i < 32; i++)
        xy[i+32] = sy[i];
    
    return;
}

    /*

    fe recip;
    fe x;
    fe y;
    
    printf("%s","\n-----------------------ge_p3-------------------------------\n");
    fe_tobytes(s, A.X);logasuint(s,"x");
    fe_tobytes(s, A.Y);logasuint(s,"y");

    fe_tobytes(s, A.Z);logasuint(s,"z");
    fe_invert(recip, A.Z);
    fe_tobytes(s, recip);logasuint(s,"zinv");
    fe_mul(x, A.X, recip);
    fe_tobytes(s, x);logasuint(s,"zinv*x");

    fe_mul(y, A.Y, recip);
    fe_tobytes(s, y);logasuint(s,"zinv*x*y");

    fe_tobytes(s, y);
    //s[31] ^= fe_isnegative(x) << 7;

    
    //void ge_p3_dbl(ge_p1p1 *r, const ge_p3 *p);
    //void ge_p3_to_cached(ge_cached *r, const ge_p3 *p);
    //void ge_p3_to_p2(ge_p2 *r, const ge_p3 *p);    
    
    printf("%s","\n-----------------------ge_p3_dbl-------------------------------\n");
    ge_p1p1 B;
    ge_p3_dbl(&B, &A);
    fe_tobytes(s, B.X);logasuint(s,"x");
    fe_tobytes(s, B.Y);logasuint(s,"y");
    fe_tobytes(s, B.Z);logasuint(s,"z");
    fe_invert(recip, B.Z);
    fe_tobytes(s, recip);logasuint(s,"zinv");
    
    fe_mul(x, B.X, recip);
    fe_tobytes(s, x);logasuint(s,"zinv*x");

    fe_mul(y, B.Y, recip);
    fe_tobytes(s, y);logasuint(s,"zinv*x*y");    

    printf("%s","\n-----------------------ge_p3_to_cached-------------------------------\n");
    ge_cached C;
    ge_p3_to_cached(&C, &A);;
    fe_tobytes(s, C.YplusX);logasuint(s,"YplusX");
    fe_tobytes(s, C.YminusX);logasuint(s,"YminusX");
    fe_tobytes(s, C.Z);logasuint(s,"z");
    fe_invert(recip, C.Z);
    fe_tobytes(s, recip);logasuint(s,"zinv");
    
    fe_mul(x, C.YplusX, recip);
    fe_tobytes(s, x);logasuint(s,"zinv*YplusX");

    fe_mul(y, C.YminusX, recip);
    fe_tobytes(s, y);logasuint(s,"zinv*YplusX*y");    
    
    printf("%s","\n----------------------ge_p3_to_p2--------------------------------\n");
    ge_p2 D;
    ge_p3_to_p2(&D, &A);;
    fe_tobytes(s, D.X);logasuint(s,"x");
    fe_tobytes(s, D.Y);logasuint(s,"y");
    fe_tobytes(s, D.Z);logasuint(s,"z");
    fe_invert(recip, D.Z);
    fe_tobytes(s, recip);logasuint(s,"zinv");
    
    fe_mul(x, D.X, recip);
    fe_tobytes(s, x);logasuint(s,"zinv*x");

    fe_mul(y, D.Y, recip);
    fe_tobytes(s, y);logasuint(s,"zinv*x*y"); 
    */           