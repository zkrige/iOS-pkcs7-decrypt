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

      guard let decrypted = ScriptDecrypt.decrypt(enc, privateKey: pKey, certificate: certificate) else {
          throw "invalid encrypted script"
      }
      return decrypted
    }
}
```
