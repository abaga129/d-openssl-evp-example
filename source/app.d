import dplug.core.sharedlib;
import dplug.core;

import core.stdc.stdlib;
import core.stdc.string;
import core.stdc.stdio;

import deimos.openssl.evp;
import deimos.openssl.conf;
import deimos.openssl.err;

void main() nothrow @nogc
{
    /*
     * Set up the key and iv. Do I need to say to not hard code these in a
     * real application? :-)
     */

    /* A 256 bit key */
    ubyte *key = cast(ubyte *)"01234567890123456789012345678901";

    /* A 128 bit IV */
    ubyte *iv = cast(ubyte *)"0123456789012345";

    /* Message to be encrypted */
    ubyte *plaintext =
        cast(ubyte *)"The quick brown fox jumps over the lazy dog";

    /*
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */
    ubyte[128] ciphertext;

    /* Buffer for the decrypted text */
    ubyte[128] decryptedtext;

    int decryptedtext_len, ciphertext_len;

    /* Encrypt the plaintext */
    ciphertext_len = encrypt (plaintext, cast(int)strlen (cast(char *)plaintext), key, iv,
                              ciphertext.ptr);

    /* Do something useful with the ciphertext here */
    printf("Ciphertext is:\n");
    assumeNothrowNoGC(&BIO_dump_fp)(stdout, cast(const char *)ciphertext, ciphertext_len);

    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(ciphertext.ptr, ciphertext_len, key, iv,
                                decryptedtext.ptr);

    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext.ptr);
}

void test() nothrow @nogc
{
	SharedLib sharedLib;
	sharedLib.load("libcrypto.so.1.1");

	if(sharedLib.hasSymbol("EVP_DecryptInit_ex"))
	{
		printf("Yaaasss");
		sharedLib.loadSymbol("DES_decrypt3");
	}
	else
	{
		printf("error");
	}
}

int encrypt(ubyte *plaintext, int plaintext_len, ubyte *key,
            ubyte *iv, ubyte *ciphertext) nothrow @nogc
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
	ctx = assumeNothrowNoGC(&EVP_CIPHER_CTX_new)();
    if(!(ctx))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != assumeNothrowNoGC(&EVP_EncryptInit_ex)(ctx, assumeNothrowNoGC(&EVP_aes_256_cbc)(), null, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != assumeNothrowNoGC(&EVP_EncryptUpdate)(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != assumeNothrowNoGC(&EVP_EncryptFinal_ex)(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    assumeNothrowNoGC(&EVP_CIPHER_CTX_free)(ctx);

    return ciphertext_len;
}

int decrypt(ubyte *ciphertext, int ciphertext_len, ubyte *key,
            ubyte *iv, ubyte *plaintext) nothrow @nogc
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
	ctx = assumeNothrowNoGC(&EVP_CIPHER_CTX_new)();
    if(!(ctx))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != assumeNothrowNoGC(&EVP_DecryptInit_ex)(ctx, assumeNothrowNoGC(&EVP_aes_256_cbc)(), null, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != assumeNothrowNoGC(&EVP_DecryptUpdate)(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != assumeNothrowNoGC(&EVP_DecryptFinal_ex)(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    assumeNothrowNoGC(&EVP_CIPHER_CTX_free)(ctx);

    return plaintext_len;
}

void handleErrors() nothrow @nogc
{
    assumeNothrowNoGC(&ERR_print_errors_fp)(stderr);
    abort();
}