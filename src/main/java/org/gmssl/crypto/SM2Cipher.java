package org.gmssl.crypto;

import javax.crypto.*;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author yongfeili
 * @date 2024/8/2
 * @description
 */
public class SM2Cipher extends CipherSpi {

    private Key key;
    private int opmode;

    @Override
    protected void engineSetMode(String s) throws NoSuchAlgorithmException {
        // 实现加密模式设置，SM2不需要设置模式，可以留空
    }

    @Override
    protected void engineSetPadding(String s) throws NoSuchPaddingException {
        // 实现填充方式设置，SM2不需要填充，可以留空
    }

    @Override
    protected int engineGetBlockSize() {
        // SM2 是流加密，没有块大小
        return 0;
    }

    @Override
    protected int engineGetOutputSize(int i) {
        // 根据输入长度计算输出长度
        // 这里只是示例，具体实现需要根据实际情况调整
        // 例如，假设增加一个固定长度的输出
        return i+32;
    }

    @Override
    protected byte[] engineGetIV() {
        // SM2 不使用 IV，可以返回 null
        return new byte[0];
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        // SM2 不使用参数，可以返回 null
        return null;
    }

    @Override
    protected void engineInit(int i, Key key, SecureRandom secureRandom) throws InvalidKeyException {
        this.key = key;
        this.opmode = i;
    }

    @Override
    protected void engineInit(int i, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {

    }

    @Override
    protected void engineInit(int i, Key key, AlgorithmParameters algorithmParameters, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {

    }

    @Override
    protected byte[] engineUpdate(byte[] bytes, int i, int i1) {
        return new byte[0];
    }

    @Override
    protected int engineUpdate(byte[] bytes, int i, int i1, byte[] bytes1, int i2) throws ShortBufferException {
        return 0;
    }

    @Override
    protected byte[] engineDoFinal(byte[] bytes, int i, int i1) throws IllegalBlockSizeException, BadPaddingException {
        return new byte[0];
    }

    @Override
    protected int engineDoFinal(byte[] bytes, int i, int i1, byte[] bytes1, int i2) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return 0;
    }
}
