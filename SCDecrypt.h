//
//  SCDecrypt.h
//
//  Created by Zayin Krige on 2017/11/30.
//

#ifndef SCDecrypt_h
#define SCDecrypt_h
#include <stdio.h>

/*
decrypts a PKCS7 SMIME container with given private key and certificate
*/
char *decrypt_smime(const char *encrypted, const char *privateKey, const char *certificate);

#endif /* SCDecrypt_h */
