/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package org.gmssl.crypto.symmetric;

import org.gmssl.GmSSLException;
import org.gmssl.GmSSLJNI;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/07/27
 * @description
 *
 */
public class SM4GCM extends SM4Engine {

    public final static int MIN_IV_SIZE = GmSSLJNI.SM4_GCM_MIN_IV_SIZE;
    public final static int MAX_IV_SIZE = GmSSLJNI.SM4_GCM_MAX_IV_SIZE;
    public final static int DEFAULT_IV_SIZE = GmSSLJNI.SM4_GCM_DEFAULT_IV_SIZE;
    public final static int MIN_TAG_SIZE = 8;
    public final static int MAX_TAG_SIZE = GmSSLJNI.SM4_GCM_MAX_TAG_SIZE;

    private long sm4_gcm_ctx = 0;
    private boolean do_encrypt = true;
    private boolean inited = false;

    private byte[] iv;

    private byte[] aad;

    private Key key;

    private int tLen;

    private int offset;

    public SM4GCM(){
        super();
        ctx();
    }

    @Override
    protected void init(int opmode, Key key, SecureRandom random) throws InvalidKeyException {

    }

    @Override
    protected void init(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) {
        if (!(params instanceof GCMParameterSpec)) {
            throw new GmSSLException("need the GCMParameterSpec parameter");
        }
        this.key = key;
        this.iv = ((GCMParameterSpec) params).getIV();
        this.tLen = ((GCMParameterSpec) params).getTLen();
        this.do_encrypt = (opmode == Cipher.ENCRYPT_MODE);
    }

    @Override
    protected byte[] engineGetIV() {
        return iv;
    }

    @Override
    protected byte[] processUpdate(byte[] input, int inputOffset, int inputLen) {
        return new byte[0];
    }

    @Override
    protected int processUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        int outLen = update(input, inputOffset, inputLen, output, outputOffset);
        this.offset+=outLen;
        return outLen;
    }

    @Override
    protected int processBlock(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        processUpdate(input, inputOffset, inputLen, output, outputOffset);
        int outLen = doFinal(output, this.offset);
        outLen = outLen + this.offset;
        this.offset = 0;
        return outLen;
    }

    @Override
    protected byte[] processBlock(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        return new byte[0];
    }

    @Override
    protected void processUpdateAAD(byte[] src, int offset, int len) {
        this.aad = new byte[len];
        System.arraycopy(src, offset, this.aad, 0, len);

        init(key.getEncoded(), iv,aad,tLen, do_encrypt);
    }

    private void ctx(){
        if ((this.sm4_gcm_ctx = GmSSLJNI.sm4_gcm_ctx_new()) == 0) {
            throw new GmSSLException("");
        }
        this.inited = false;
    }

    private void init(byte[] key, byte[] iv, byte[] aad, int taglen, boolean do_encrypt){
        if (key == null
                || key.length != this.KEY_SIZE
                || iv == null
                || iv.length < this.MIN_IV_SIZE
                || iv.length > this.MAX_IV_SIZE
                || taglen < this.MIN_TAG_SIZE
                || taglen > this.MAX_TAG_SIZE) {
            throw new GmSSLException("");
        }

        if (do_encrypt == true) {
            if (GmSSLJNI.sm4_gcm_encrypt_init(this.sm4_gcm_ctx, key, iv, aad, taglen) != 1) {
                throw new GmSSLException("");
            }
        } else {
            if (GmSSLJNI.sm4_gcm_decrypt_init(this.sm4_gcm_ctx, key, iv, aad, taglen) != 1) {
                throw new GmSSLException("");
            }
        }

        this.do_encrypt = do_encrypt;
        this.inited = true;
    }

    private int update(byte[] in, int in_offset, int inlen, byte[] out, int out_offset){
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
            if ((outlen = GmSSLJNI.sm4_gcm_encrypt_update(this.sm4_gcm_ctx, in, in_offset, inlen, out, out_offset)) < 0) {
                throw new GmSSLException("");
            }
        } else {
            if ((outlen = GmSSLJNI.sm4_gcm_decrypt_update(this.sm4_gcm_ctx, in, in_offset, inlen, out, out_offset)) < 0) {
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
            if ((outlen = GmSSLJNI.sm4_gcm_encrypt_finish(this.sm4_gcm_ctx, out, out_offset)) < 0) {
                throw new GmSSLException("");
            }
        } else {
            if ((outlen = GmSSLJNI.sm4_gcm_decrypt_finish(this.sm4_gcm_ctx, out, out_offset)) < 0) {
                throw new GmSSLException("");
            }
        }

        this.inited = false;
        return outlen;
    }
}
