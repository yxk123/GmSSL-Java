package org.gmssl.crypto;

import java.security.PrivilegedAction;
import java.security.Provider;

/**
 * @author yongfeili
 * @date 2024/8/2
 * @description
 */
public class GmSSLProvider extends Provider {

    public GmSSLProvider() {
        super("GmSSL", "3.1.1", "GmSSL Provider");

        put("Cipher.SM2", "org.gmssl.crypto.SM2Cipher");
        put("KeyFactory.SM2", "org.gmssl.crypto.SM2KeyFactory");
        put("KeyPairGenerator.SM2", "org.gmssl.crypto.SM2KeyPairGenerator");
        put("Signature.SM2", "org.gmssl.crypto.SM2Signature");
    }


}
