package org.gmssl.crypto;

import org.gmssl.GmSSLException;
import org.gmssl.GmSSLJNI;

import java.security.SecureRandomSpi;

/**
 * @author yongfeili
 * @date 2024/8/12
 * @description
 */
public class Random extends SecureRandomSpi {

    public Random() {
        super();
    }

    @Override
    protected void engineSetSeed(byte[] seed) {

    }

    @Override
    protected void engineNextBytes(byte[] bytes) {
        randBytes(bytes,0, bytes.length);
    }

    @Override
    protected byte[] engineGenerateSeed(int numBytes) {
        return randBytes(numBytes);
    }

    public byte[] randBytes(int len) {
        byte[] out = new byte[len];
        if (GmSSLJNI.rand_bytes(out, 0, len) != 1) {
            throw new GmSSLException("");
        }
        return out;
    }

    public void randBytes(byte[] out, int offset, int len) {
        if (out == null
                || offset < 0
                || len < 0
                || offset + len <= 0
                || out.length < offset + len) {
            throw new GmSSLException("");
        }
        if (GmSSLJNI.rand_bytes(out, offset, len) != 1) {
            throw new GmSSLException("");
        }
    }
}
