//
//  SCDecrypt.h
//  Scriptabl
//
//  Created by Zayin Krige on 2017/11/30.
//  Copyright © 2017 Scriptabl. All rights reserved.
//

#ifndef SCDecrypt_h
#define SCDecrypt_h

#include <stdio.h>

char *decrypt_smime(const char *encrypted, const char *privateKey, const char *certificate);

#endif /* SCDecrypt_h */
