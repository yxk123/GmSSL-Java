package org.gmssl.crypto.asymmetric;

import org.gmssl.GmSSLException;
import org.gmssl.GmSSLJNI;

import javax.crypto.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author yongfeili
 * @date 2024/8/2
 * @description
 */
public class SM2Cipher extends CipherSpi {

    private int mode;
    private SM2Key key;
    private SecureRandom random;
    private ByteBuffer buffer;

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (!mode.equalsIgnoreCase("ECB")) {
            throw new NoSuchAlgorithmException("Unsupported mode: " + mode);
        }
        // SM2 只支持 ECB 模式
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!padding.equalsIgnoreCase("NoPadding")) {
            throw new NoSuchPaddingException("Unsupported padding: " + padding);
        }
        // SM2 不使用填充
    }

    @Override
    protected int engineGetBlockSize() {
        // SM2 是流加密，没有块大小
        return 0;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        // 根据输入长度计算输出长度
        // 这里只是示例，具体实现需要根据实际情况调整
        // 例如，假设增加一个固定长度的输出
        return inputLen+32;
    }

    @Override
    protected byte[] engineGetIV() {
        // // SM2 不使用 IV
        return null;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        // SM2 不使用参数
        return null;
    }

    @Override
    protected void engineInit(int mode, Key key, SecureRandom secureRandom) throws InvalidKeyException {
        if (!(key instanceof SM2Key)) {
            throw new InvalidKeyException("Invalid key type");
        }
        this.key = (SM2Key)key;
        this.mode = mode;
        this.random = (secureRandom != null) ? secureRandom : new SecureRandom();
        // 初始化缓冲区
        this.buffer = ByteBuffer.allocate(2048);
    }

    @Override
    protected void engineInit(int mode, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(mode, key, random);
    }

    @Override
    protected void engineInit(int i, Key key, AlgorithmParameters algorithmParameters, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(mode, key, random);
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
        return 0;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        buffer.put(input, inputOffset, inputLen);
        byte[] data = new byte[buffer.position()];
        buffer.flip();
        buffer.get(data);

        if (mode == Cipher.ENCRYPT_MODE) {
            return encrypt(data);
        } else if (mode == Cipher.DECRYPT_MODE) {
            return decrypt(data);
        } else {
            throw new GmSSLException("Cipher not initialized properly");
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] result = engineDoFinal(input, inputOffset, inputLen);
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }

    public byte[] encrypt(byte[] plaintext) {
        if (this.key.sm2_key == 0) {
            throw new GmSSLException("");
        }
        if (plaintext == null
                || plaintext.length > this.key.MAX_PLAINTEXT_SIZE) {
            throw new GmSSLException("");
        }

        byte[] ciphertext;
        if ((ciphertext = GmSSLJNI.sm2_encrypt(this.key.sm2_key, plaintext)) == null) {
            throw new GmSSLException("");
        }
        return ciphertext;
    }

    public byte[] decrypt(byte[] ciphertext) {
        if (this.key.sm2_key == 0) {
            throw new GmSSLException("");
        }
        if (this.key.has_private_key == false) {
            throw new GmSSLException("");
        }
        if (ciphertext == null) {
            throw new GmSSLException("");
        }

        byte[] plaintext;
        if ((plaintext = GmSSLJNI.sm2_decrypt(this.key.sm2_key, ciphertext)) == null) {
            throw new GmSSLException("");
        }
        return plaintext;
    }
}
