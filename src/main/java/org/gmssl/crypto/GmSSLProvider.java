package org.gmssl.crypto;

import java.security.Provider;

/**
 * @author yongfeili
 * @date 2024/8/2
 * @description
 */
public class GmSSLProvider extends Provider {

    protected GmSSLProvider() {
        super("GmSSL", 1.0, "GmSSL Provider v1.0");

        // 注册Cipher
        put("Cipher.SM2", "org.gmssl.crypto.SM2Cipher");

        // 注册KeyPairGenerator
        put("KeyPairGenerator.SM2", "org.gmssl.crypto.SM2KeyPairGenerator");

        // 注册KeyFactory
        put("KeyFactory.SM2", "org.gmssl.crypto.SM2KeyFactory");

        // 注册Signature
        put("Signature.SM2", "org.gmssl.crypto.SM2Signature");

    }


}
