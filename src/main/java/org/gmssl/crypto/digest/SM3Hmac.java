package org.gmssl.crypto.digest;

import org.gmssl.GmSSLException;
import org.gmssl.GmSSLJNI;

import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author yongfeili
 * @date 2024/8/12
 * @description
 */
public class SM3Hmac extends MacSpi {

    private final static int MAC_SIZE = GmSSLJNI.SM3_HMAC_SIZE;

    private Key key;

    private long sm3_hmac_ctx = 0;

    public SM3Hmac() {
        super();
        ctx();
    }

    public SM3Hmac(Key key){
        this.key = key;
        ctx();
        init();
    }

    @Override
    protected int engineGetMacLength() {
        return MAC_SIZE;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (!(key instanceof SecretKey)) {
            throw new GmSSLException("Invalid key for HMAC-SM3");
        }
        this.key = key;
        init();
    }

    @Override
    protected void engineUpdate(byte input) {
        byte[] data = new byte[]{input};
        this.update(data, 0, data.length);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        this.update(input, 0, len);
    }

    @Override
    protected byte[] engineDoFinal() {
        return generateMac();
    }

    @Override
    protected void engineReset() {
        this.reset(this.key);
    }

    public void engineReset(Key key) {
        this.reset(key);
    }

    private void ctx(){
        if ((this.sm3_hmac_ctx = GmSSLJNI.sm3_hmac_ctx_new()) == 0) {
            throw new GmSSLException("");
        }
    }

    private void init() {
        if (GmSSLJNI.sm3_hmac_init(this.sm3_hmac_ctx, key.getEncoded()) != 1) {
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
        if (GmSSLJNI.sm3_hmac_update(this.sm3_hmac_ctx, data, offset, len) != 1) {
            throw new GmSSLException("");
        }
    }

    public void update(byte[] data) {
        this.update(data, 0, data.length);
    }

    public byte[] generateMac() {
        byte[] mac = new byte[this.MAC_SIZE];
        if (GmSSLJNI.sm3_hmac_finish(this.sm3_hmac_ctx, mac) != 1) {
            throw new GmSSLException("");
        }
        if (GmSSLJNI.sm3_hmac_init(this.sm3_hmac_ctx, this.key.getEncoded()) != 1) {
            throw new GmSSLException("");
        }
        return mac;
    }

    public void reset(Key key) {
        if (key == null) {
            throw new GmSSLException("");
        }
        if (GmSSLJNI.sm3_hmac_init(this.sm3_hmac_ctx, key.getEncoded()) != 1) {
            throw new GmSSLException("");
        }
        this.key = key;
    }
}
