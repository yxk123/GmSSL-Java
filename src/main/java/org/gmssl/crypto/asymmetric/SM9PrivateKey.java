package org.gmssl.crypto.asymmetric;

import java.security.PrivateKey;
import java.security.spec.KeySpec;

/**
 * @author yongfeili
 * @date 2024/8/20
 * @description
 */
public abstract class SM9PrivateKey implements PrivateKey {

    @Override
    public String getAlgorithm() {
        return null;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return new byte[0];
    }

    public abstract KeySpec getSecretKey();

    public abstract void importEncryptedPrivateKeyInfoPem(String pass, String file);

    public abstract void exportEncryptedPrivateKeyInfoPem(String pass, String file);

    public byte[] decrypt(byte[] ciphertext) {
        return null;
    }

    public byte[] sign(long sign_ctx) {
        return null;
    }
}
