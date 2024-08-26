package org.gmssl.crypto.symmetric;

import org.gmssl.GmSSLJNI;

import javax.crypto.SecretKey;

/**
 * @author yongfeili
 * @date 2024/8/26
 * @description
 */
public class ZucKey implements SecretKey {

    public final static int KEY_SIZE = GmSSLJNI.ZUC_KEY_SIZE;

    private byte[] key;

    public ZucKey(byte[] key){
        this.key = key;
    }

    @Override
    public String getAlgorithm() {
        return "ZUC";
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return key;
    }
}
