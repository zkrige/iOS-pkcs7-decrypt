//
//  ScriptDecrypt.h
//  Scriptabl
//
//  Created by Zayin Krige on 2017/11/30.
//  Copyright © 2017 Scriptabl. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ScriptDecrypt : NSObject
+ (NSString *)decrypt:(NSString *)encrypted privateKey:(NSString *)privateKey certificate:(NSString *)certificate ;
@end
