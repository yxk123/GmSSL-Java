package org.gmssl.crypto;

import org.gmssl.GmSSLException;
import org.gmssl.GmSSLJNI;

import java.security.PrivateKey;

/**
 * @author yongfeili
 * @date 2024/8/7
 * @description
 */
public class SM2PrivateKey extends SM2Key implements PrivateKey{

    public SM2PrivateKey() {
        super();
    }

    public SM2PrivateKey(long sm2_key) {
        super(sm2_key, true);
    }

    public SM2PrivateKey(long sm2_key, boolean has_private_key) {
        super(sm2_key,has_private_key);
    }

    public String getAlgorithm() {
        return "SM2";
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return exportPrivateKeyInfoDer();
    }

    private byte[] exportPrivateKeyInfoDer() {
        if (this.sm2_key == 0) {
            throw new GmSSLException("");
        }
        if (this.has_private_key == false) {
            throw new GmSSLException("");
        }
        byte[] der;
        if ((der = GmSSLJNI.sm2_private_key_info_to_der(this.sm2_key)) == null) {
            throw new GmSSLException("");
        }
        return der;
    }

}
