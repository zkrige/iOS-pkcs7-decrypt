//
//  ScriptDecrypt.m
//  Scriptabl
//
//  Created by Zayin Krige on 2017/11/30.
//  Copyright © 2017 Scriptabl. All rights reserved.
//

#import "ScriptDecrypt.h"
#import "SCDecrypt.h"

@implementation ScriptDecrypt

+ (NSString *)decrypt:(NSString *)encrypted privateKey:(NSString *)privateKey certificate:(NSString *)certificate {
    const char *enc = [encrypted UTF8String];
    const char *pk = [privateKey UTF8String];
    const char *cert = [certificate UTF8String];
    const char *decrypted = decrypt_smime(enc, pk, cert);
    if (decrypted) {
        return [NSString stringWithUTF8String:decrypted];
    } else {
        return nil;
    }
}
@end
