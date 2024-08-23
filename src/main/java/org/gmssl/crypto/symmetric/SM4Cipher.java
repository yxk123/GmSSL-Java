package org.gmssl.crypto.symmetric;

import javax.crypto.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author yongfeili
 * @date 2024/8/12
 * @description
 */
public class SM4Cipher extends CipherSpi {

    private SM4Engine sm4Engine;

    public SM4Cipher() {
        super();
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        // 设置加密模式
        this.sm4Engine = SM4CipherFactory.createCipher(mode);
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        // 设置填充方式，可以选择支持PKCS5Padding，NoPadding等
        System.out.println("padding2:" + padding);
    }

    @Override
    protected int engineGetBlockSize() {
        // SM4块大小为16字节
        return SM4Engine.BLOCK_SIZE;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        // 输出大小根据模式和填充计算
        return 0;
    }

    @Override
    protected byte[] engineGetIV() {
        // ECB模式不使用IV
        return sm4Engine.engineGetIV();
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        // 无需额外的参数
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {

    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        sm4Engine.engineInit(opmode, key, params, random);

    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {

    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {

        return null;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        int outLen = sm4Engine.engineUpdate(input, inputOffset, inputLen, output, outputOffset);
        return outLen;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {

        return null;
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        int outLen = sm4Engine.engineDoFinal(input, inputOffset, inputLen, output, outputOffset);
        return outLen;
    }

    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len) {
        sm4Engine.engineUpdateAAD(src, offset, len);
    }

}
