package org.gmssl.crypto;

import java.security.Provider;

/**
 * @author yongfeili
 * @date 2024/8/2
 * @description
 */
public class GmSSLProvider extends Provider {

    public GmSSLProvider() {
        super("GmSSL", "3.1.1", "GmSSL Provider");

        put("SecureRandom.Random", "org.gmssl.crypto.Random");
        put("Cipher.SM2", "org.gmssl.crypto.asymmetric.SM2Cipher");
        put("KeyPairGenerator.SM2", "org.gmssl.crypto.asymmetric.SM2KeyPairGenerator");
        put("Signature.SM2", "org.gmssl.crypto.asymmetric.SM2Signature");

        put("MessageDigest.SM3", "org.gmssl.crypto.digest.SM3Digest");
        put("Mac.SM3Hmac", "org.gmssl.crypto.digest.SM3Hmac");
        put("SecretKeyFactory.SM3Pbkdf2", "org.gmssl.crypto.digest.SM3Pbkdf2");

        put("Cipher.SM4", "org.gmssl.crypto.symmetric.SM4Cipher");

        put("Cipher.SM9", "org.gmssl.crypto.asymmetric.SM9Cipher");
        put("Signature.SM9", "org.gmssl.crypto.asymmetric.SM9Signature");
        put("KeyPairGenerator.SM9", "org.gmssl.crypto.asymmetric.SM9KeyPairGeneratorSpi");

        put("Cipher.ZUC", "org.gmssl.crypto.symmetric.ZucCipher");
    }


}
