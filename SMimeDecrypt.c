//
//  SMimeDecrypt.c
//
//  Created by Zayin Krige on 2017/11/30.
//

#include "SMimeDecrypt.h"
#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

/*
converts PEM encoded certificate to X509
*/
X509 *getCert(const char *certificate) {
    BIO *membuf = BIO_new(BIO_s_mem());
    BIO_puts(membuf, certificate);
    X509 *x509 = PEM_read_bio_X509(membuf, NULL, NULL, NULL);
    return x509;
}

/*
converts PEM encoded private key
*/
EVP_PKEY *getKey(const char *privateKey) {
    BIO *membuf = BIO_new(BIO_s_mem());
    BIO_puts(membuf, privateKey);
    EVP_PKEY *key = PEM_read_bio_PrivateKey(membuf, NULL, 0, NULL);
    return key;
}


/*
converts SMIME Container
*/
PKCS7 *getContainer(const char *encrypted) {
    BIO* membuf = BIO_new(BIO_s_mem());
    //see error here - http://openssl.6102.n7.nabble.com/SMIME-read-PKCS7-fails-with-memory-BIO-but-works-with-file-BIO-td7673.html
    //if we dont set this, then we get error: 218542222
    //This error, converted to hexadecimal, is 0xd06b08e which when used in 
    //$ `openssl errstr d06b08e` gives 
    //error:0D06B08E:asn1 encoding routines:ASN1_d2i_bio:not enough data 
    BIO_set_mem_eof_return(membuf, 0); 
    BIO_puts(membuf, encrypted);
    PKCS7* pkcs7 = SMIME_read_PKCS7(membuf, NULL);
    if (!pkcs7) {
        fprintf(stderr, "File BIO case, error: %ld\n", ERR_get_error());
    }
    return pkcs7;
}

/*
decrypts the SMIME container
*/
char *decrypt(PKCS7 *pkcs7, EVP_PKEY *pkey, X509 *cert) {

    BIO *out = BIO_new(BIO_s_mem());
    if (PKCS7_decrypt(pkcs7, pkey, cert, out, 0) != 1) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        PKCS7_free(pkcs7);
        fprintf(stderr, "Error decrypting PKCS#7 object\n");
        return NULL;
    }
    BUF_MEM* mem;
    BIO_get_mem_ptr(out, &mem);
    char *data = malloc(mem->length + 1);
    memcpy(data, mem->data, mem->length + 1);
    BIO_flush(out);
    BIO_free(out);
    return data;

}
/*
decrypts a PKCS7 SMIME container with given private key and certificate
*/
char *decrypt_smime(const char *encrypted, const char *privateKey, const char *certificate) {

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    X509 *cert = getCert(certificate);
    if (!cert) {
        return NULL;
    }

    EVP_PKEY *pkey = getKey(privateKey);
    if (!pkey) {
        X509_free(cert);
        return NULL;
    }

    PKCS7 *pkcs7 = getContainer(encrypted);
    if (!pkcs7) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return NULL;
    }

    char *data = decrypt(pkcs7, pkey, cert);

    X509_free(cert);
    EVP_PKEY_free(pkey);
    PKCS7_free(pkcs7);

    return data;
}

