package org.gmssl.crypto.asymmetric;

import org.gmssl.Sm9SignMasterKey;

import java.security.PublicKey;

/**
 * @author yongfeili
 * @date 2024/8/20
 * @description
 */
public abstract class SM9PublicKey implements PublicKey {

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

    public abstract long getPublicKey();

    public abstract void importPublicKeyPem(String file);

    public abstract void exportPublicKeyPem(String file);

    public byte[] encrypt(byte[] plaintext, String id){
        return null;
    };

    public Boolean verify(byte[] signature, String id,long sign_ctx){
        return null;
    }
}
