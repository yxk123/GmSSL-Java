package org.gmssl.crypto.asymmetric;

import org.gmssl.GmSSLException;
import org.gmssl.GmSSLJNI;

import java.security.*;
/**
 * @author yongfeili
 * @date 2024/8/2
 * @description
 */
public class SM2KeyPairGenerator extends KeyPairGeneratorSpi {

    private long sm2_key = 0;
    private boolean has_private_key = false;

    @Override
    public void initialize(int keysize, SecureRandom random) {
        generateKey();
    }

    @Override
    public KeyPair generateKeyPair() {
        PublicKey publicKey = new SM2PublicKey(sm2_key, has_private_key);
        PrivateKey privateKey = new SM2PrivateKey(sm2_key, has_private_key);
        return new KeyPair(publicKey, privateKey);
    }

    private void generateKey() {
        if (this.sm2_key != 0) {
            GmSSLJNI.sm2_key_free(this.sm2_key);
        }
        if ((sm2_key = GmSSLJNI.sm2_key_generate()) == 0) {
            throw new GmSSLException("");
        }
        this.has_private_key = true;
    }

}
