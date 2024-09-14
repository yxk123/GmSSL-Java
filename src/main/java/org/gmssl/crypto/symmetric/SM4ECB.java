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

import javax.crypto.*;
import java.nio.ByteBuffer;
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
public class SM4ECB extends SM4Engine {

    public final static int KEY_SIZE = GmSSLJNI.SM4_KEY_SIZE;
    public final static int BLOCK_SIZE = GmSSLJNI.SM4_BLOCK_SIZE;

    private Key key;
    private long sm4_key = 0;

    private boolean do_encrypt = false;

    private ByteBuffer buffer;

    @Override
    protected void init(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        if (!(key instanceof SecretKey)) {
            throw new GmSSLException("Invalid KeySpec");
        }
        this.do_encrypt = (opmode == Cipher.ENCRYPT_MODE);
        this.key = key;
        // 初始化缓冲区
        this.buffer = ByteBuffer.allocate(2048);
        init();
    }

    @Override
    protected void init(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) {

    }

    @Override
    protected byte[] engineGetIV() {
        return null;
    }

    @Override
    protected byte[] processUpdate(byte[] input, int inputOffset, int inputLen) {
        putBytes(input, inputOffset, inputLen);
        return null;
    }

    @Override
    protected int processUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        putBytes(input, inputOffset, inputLen);
        return 0;
    }

    @Override
    protected int processBlock(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {

        return 0;
    }

    @Override
    protected byte[] processBlock(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        putBytes(input, inputOffset, inputLen);
        byte[] data = new byte[buffer.position()];
        buffer.flip();
        buffer.get(data);

        byte[] output = new byte[buffer.position()];
        encrypt(data,0,output,0);
        buffer.clear();
        return output;
    }

    private void putBytes(byte[] input, int inputOffset, int inputLen){
        if(buffer.remaining()<inputLen){
            ByteBuffer newByteBuffer=ByteBuffer.allocate(buffer.capacity()+inputLen);
            buffer.flip();
            newByteBuffer.put(buffer);
            buffer=newByteBuffer;
        }
        buffer.put(input, inputOffset, inputLen);
    }

    private void init(){
        if ((sm4_key = GmSSLJNI.sm4_key_new()) == 0) {
            throw new GmSSLException("");
        }

        if (do_encrypt == true) {
            if (GmSSLJNI.sm4_set_encrypt_key(sm4_key, key.getEncoded()) != 1) {
                throw new GmSSLException("");
            }
        } else {
            if (GmSSLJNI.sm4_set_decrypt_key(sm4_key, key.getEncoded()) != 1) {
                throw new GmSSLException("");
            }
        }
    }

    private void encrypt(byte[] in, int in_offset, byte[] out, int out_offset) {
        if (in == null
                || in_offset < 0
                || in_offset + this.BLOCK_SIZE <= 0
                || in_offset + this.BLOCK_SIZE > in.length) {
            throw new GmSSLException("");
        }
        if (out == null
                || out_offset < 0
                || out_offset + this.BLOCK_SIZE <= 0
                || out_offset + this.BLOCK_SIZE > in.length) {
            throw new GmSSLException("");
        }

        if (GmSSLJNI.sm4_encrypt(sm4_key, in, in_offset, out, out_offset) != 1) {
            throw new GmSSLException("");
        }
    }
}
