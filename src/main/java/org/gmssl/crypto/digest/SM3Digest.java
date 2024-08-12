package org.gmssl.crypto.digest;

import org.gmssl.GmSSLException;
import org.gmssl.GmSSLJNI;

import java.security.MessageDigestSpi;

/**
 * @author yongfeili
 * @date 2024/8/12
 * @description
 */
public class SM3Digest extends MessageDigestSpi {

    private final static int DIGEST_SIZE = GmSSLJNI.SM3_DIGEST_SIZE;

    private long sm3_ctx = 0;

    public SM3Digest() {
        init();
    }

    @Override
    protected void engineUpdate(byte input) {
        byte[] data = new byte[]{input};
        this.update(data, 0, data.length);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        this.update(input, offset, len);
    }

    @Override
    protected byte[] engineDigest() {
        return this.digest();
    }

    @Override
    protected void engineReset() {
        this.reset();
    }

    private void init(){
        if ((sm3_ctx = GmSSLJNI.sm3_ctx_new()) == 0) {
            throw new GmSSLException("");
        }
        if (GmSSLJNI.sm3_init(sm3_ctx) != 1) {
            throw new GmSSLException("");
        }
    }

    public void update(byte[] data, int offset, int len) {
        if (data == null
                || offset < 0
                || len < 0
                || offset + len <= 0
                || data.length < offset + len) {
            throw new GmSSLException("");
        }
        if (GmSSLJNI.sm3_update(sm3_ctx, data, offset, len) != 1) {
            throw new GmSSLException("");
        }
    }

    public byte[] digest() {
        byte[] dgst = new byte[DIGEST_SIZE];
        if (GmSSLJNI.sm3_finish(sm3_ctx, dgst) != 1) {
            throw new GmSSLException("");
        }
        if (GmSSLJNI.sm3_init(sm3_ctx) != 1) {
            throw new GmSSLException("");
        }
        return dgst;
    }

    public void reset() {
        if (GmSSLJNI.sm3_init(sm3_ctx) != 1) {
            throw new GmSSLException("");
        }
    }

}
