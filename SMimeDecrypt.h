//
//  SCDecrypt.h
//
//  Created by Zayin Krige on 2017/11/30.
//

#ifndef SMimeDecrypt_h
#define SMimeDecrypt_h
#include <stdio.h>

/*
decrypts a PKCS7 SMIME container with given private key and certificate
*/
char *decrypt_smime(const char *encrypted, const char *privateKey, const char *certificate);

#endif /* SMimeDecrypt_h */
