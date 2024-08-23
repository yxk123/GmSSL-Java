package org.gmssl.crypto.symmetric;

import org.gmssl.GmSSLException;
import org.gmssl.GmSSLJNI;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author yongfeili
 * @date 2024/8/12
 * @description
 */
public class SM4CBC extends SM4Engine {

    public final static int IV_SIZE = GmSSLJNI.SM4_BLOCK_SIZE;

    private long sm4_cbc_ctx = 0;

    private byte[] iv;

    private boolean do_encrypt = true;

    private boolean inited = false;

    private int offset = 0;

    public SM4CBC() {
        super();
        ctx();
    }


    @Override
    protected byte[] engineGetIV() {
        return iv;
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random){
        if (!(params instanceof IvParameterSpec)) {
            throw new GmSSLException("need the IvParameterSpec parameter");
        }
        this.iv = ((IvParameterSpec) params).getIV();
        this.do_encrypt = (opmode == Cipher.ENCRYPT_MODE);
        init(key.getEncoded(), iv, do_encrypt);
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        int outLen = update(input, inputOffset, inputLen, output, outputOffset);
        this.offset+=outLen;
        return outLen;
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        this.engineUpdate(input, inputOffset, inputLen, output, outputOffset);
        int outLen = doFinal(output, this.offset);
        outLen = outLen + this.offset;
        this.offset = 0;
        return outLen;
    }

    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len) {

    }

    private void ctx() {
        if ((this.sm4_cbc_ctx = GmSSLJNI.sm4_cbc_ctx_new()) == 0) {
            throw new GmSSLException("");
        }
        this.inited = false;
    }

    private void init(byte[] key, byte[] iv, boolean do_encrypt) {
        if (key == null
                || key.length != this.KEY_SIZE
                || iv == null
                || iv.length != this.IV_SIZE) {
            throw new GmSSLException("");
        }

        if (do_encrypt == true) {
            if (GmSSLJNI.sm4_cbc_encrypt_init(this.sm4_cbc_ctx, key, iv) != 1) {
                throw new GmSSLException("");
            }
        } else {
            if (GmSSLJNI.sm4_cbc_decrypt_init(this.sm4_cbc_ctx, key, iv) != 1) {
                throw new GmSSLException("");
            }
        }

        this.do_encrypt = do_encrypt;
        this.inited = true;
    }

    private int update(byte[] in, int in_offset, int inlen, byte[] out, int out_offset) {
        if (this.inited == false) {
            throw new GmSSLException("");
        }

        if (in == null
                || in_offset < 0
                || inlen < 0
                || in_offset + inlen <= 0
                || in.length < in_offset + inlen) {
            throw new GmSSLException("");
        }
        if (out == null
                || out_offset < 0
                || out.length < out_offset) {
            throw new GmSSLException("");
        }

        int outlen;
        if (this.do_encrypt) {
            if ((outlen = GmSSLJNI.sm4_cbc_encrypt_update(this.sm4_cbc_ctx, in, in_offset, inlen, out, out_offset)) < 0) {
                throw new GmSSLException("");
            }
        } else {
            if ((outlen = GmSSLJNI.sm4_cbc_decrypt_update(this.sm4_cbc_ctx, in, in_offset, inlen, out, out_offset)) < 0) {
                throw new GmSSLException("");
            }
        }

        return outlen;
    }

    private int doFinal(byte[] out, int out_offset) {
        if (this.inited == false) {
            throw new GmSSLException("");
        }

        if (out == null
                || out_offset < 0
                || out.length < out_offset) {
            throw new GmSSLException("");
        }

        int outlen;
        if (this.do_encrypt) {
            if ((outlen = GmSSLJNI.sm4_cbc_encrypt_finish(this.sm4_cbc_ctx, out, out_offset)) < 0) {
                throw new GmSSLException("");
            }
        } else {
            if ((outlen = GmSSLJNI.sm4_cbc_decrypt_finish(this.sm4_cbc_ctx, out, out_offset)) < 0) {
                throw new GmSSLException("");
            }
        }

        this.inited = false;
        return outlen;
    }

}