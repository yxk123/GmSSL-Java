package org.gmssl.crypto.symmetric;

import org.gmssl.GmSSLException;
import org.gmssl.GmSSLJNI;

import javax.crypto.*;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;

/**
 * @author yongfeili
 * @date 2024/8/13
 * @description
 */
public class SM4 extends SM4Cipher {

    public final static int KEY_SIZE = GmSSLJNI.SM4_KEY_SIZE;
    public final static int BLOCK_SIZE = GmSSLJNI.SM4_BLOCK_SIZE;

    private Key key;
    private long sm4_key = 0;

    private boolean do_encrypt = false;

    private ByteBuffer buffer;

    @Override
    protected int engineGetBlockSize() {
        // SM4块大小为16字节
        return BLOCK_SIZE;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
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
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        buffer.put(input, inputOffset, inputLen);
        // 暂时不返回输出，等待 doFinal
        return buffer.array();
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        buffer.put(input, inputOffset, inputLen);
        // 暂时不返回输出，等待 doFinal
        return output.length;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        buffer.put(input, inputOffset, inputLen);
        byte[] data = new byte[buffer.position()];
        buffer.flip();
        buffer.get(data);

        byte[] output = new byte[buffer.position()];
        encrypt(data,0,output,0);
        buffer.clear();
        return output;
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        encrypt(input,inputOffset,output,outputOffset);
        //计算返回实际长度
        return output.length;
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

    public void encrypt(byte[] in, int in_offset, byte[] out, int out_offset) {
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
