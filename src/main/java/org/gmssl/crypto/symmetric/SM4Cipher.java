package org.gmssl.crypto.symmetric;

import org.gmssl.GmSSLException;
import org.gmssl.GmSSLJNI;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author yongfeili
 * @date 2024/8/12
 * @description
 */
public class SM4Cipher extends CipherSpi {

    public final static int KEY_SIZE = GmSSLJNI.SM4_KEY_SIZE;
    public final static int BLOCK_SIZE = GmSSLJNI.SM4_BLOCK_SIZE;

    private long sm4_key = 0;

    private Key key;

    private boolean do_encrypt = false;

    /**
     * 加密模式 CBC、CTR、GCM、ECB
     */
    private String mode;
    /**
     * 填充模式 PKCS5Padding、NoPadding等
     */
    private String padding;

    private ByteBuffer buffer;

    public SM4Cipher() {
        super();
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        // 设置加密模式
        this.mode = mode;
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        // 设置填充方式，可以选择支持PKCS5Padding，NoPadding等
        this.padding = padding;
    }

    @Override
    protected int engineGetBlockSize() {
        // SM4块大小为16字节
        return KEY_SIZE;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        // 输出大小根据模式和填充计算
        return 0;
    }

    @Override
    protected byte[] engineGetIV() {
        // ECB模式不使用IV
        return null;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        // 无需额外的参数
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        if (!(key instanceof SecretKey)) {
            throw new GmSSLException("Invalid KeySpec");
        }
        this.do_encrypt = (opmode == Cipher.ENCRYPT_MODE);
        this.key = key;
        init();
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {

    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {

    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        return new byte[0];
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        return 0;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        return new byte[0];
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        encrypt(input,inputOffset,output,outputOffset);
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
