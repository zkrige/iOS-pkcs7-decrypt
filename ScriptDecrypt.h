//
//  ScriptDecrypt.h
//
//  Created by Zayin Krige on 2017/11/30.
//

#import <Foundation/Foundation.h>

@interface ScriptDecrypt : NSObject
/*
decrypts a PKCS7 SMIME container with given private key and certificate
This is just a wrapper function around the pure c code
*/
+ (NSString *)decrypt:(NSString *)encrypted privateKey:(NSString *)privateKey certificate:(NSString *)certificate ;
@end
