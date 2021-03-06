# iOS-pkcs7-decrypt

This library requires https://github.com/krzyzanowskim/OpenSSL for the openSSL sdk.

The purpose of this library is to decrypt a signed and encrypted PKCS7 S/MIME container in iOS

Installation
- copy the file into your project

Usage
```
extension String: LocalizedError {
    public var errorDescription: String? { return self }
}


class DecryptHelper {
    public class func decrypt(encrypted: String) throws -> String {
        guard let pkData = CSRGenerator.getPrivateKeyBits(CSR.Tag) else {
            throw "invalid private key"
        }
        let pKey = "-----BEGIN RSA PRIVATE KEY-----\n" + pkData.base64EncodedString() + "\n-----END RSA PRIVATE KEY-----"
        guard let certificate = SettingsHelper.get(key: "certificate") else {
            throw "invalid certificate"
        }

        let clean = encrypted.replacingOccurrences(of: "\n", with: "")
        guard let data = Data(base64Encoded: clean) else {
            throw "invalid base64 encoded script"
        }
        let enc = String(data: data, encoding: .utf8)

        guard let decrypted = PKCS7Decrypt.decrypt(enc, privateKey: pKey, certificate: certificate) else {
            throw "invalid encrypted script"
        }
        return decrypted
    }
}
```

```
@implementation PKCS7Decrypt

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

```


To encrypt using PKCS7

```
//path is the .p7m file to encrypt
public class func encrypt(path : String) -> String {
    let data = try! Data(contentsOf: URL(string: path)!)
    let receiptBIO = BIO_new(BIO_s_mem())
    BIO_write(receiptBIO, (data as! NSData).bytes, Int32(data.count))
    let pkcs7 = d2i_PKCS7_bio(receiptBIO, nil)
    if pkcs7 == nil {
        print("??")
    }
    return pkcs7!
}



```
