package org.gmssl.crypto;

import org.gmssl.GmSSLException;
import org.gmssl.GmSSLJNI;

import java.security.Key;

/**
 * @author yongfeili
 * @date 2024/8/2
 * @description
 */
public abstract class SM2Key implements Key {

    public final static int MAX_PLAINTEXT_SIZE = GmSSLJNI.SM2_MAX_PLAINTEXT_SIZE;

    protected long sm2_key = 0;
    protected boolean has_private_key = false;

    public SM2Key() {
    }

    public SM2Key(long sm2_key, boolean has_private_key) {
        this.sm2_key = sm2_key;
        this.has_private_key = has_private_key;
    }

    @Override
    public String getAlgorithm() {
        return "SM2";
    }

    long getPrivateKey() {
        if (this.sm2_key == 0) {
            throw new GmSSLException("");
        }
        if (this.has_private_key == false) {
            throw new GmSSLException("");
        }
        return this.sm2_key;
    }

    long getPublicKey() {
        if (this.sm2_key == 0) {
            throw new GmSSLException("");
        }
        return this.sm2_key;
    }

}
