package org.gmssl.crypto.symmetric;

import org.gmssl.GmSSLJNI;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author yongfeili
 * @date 2024/8/14
 * @description
 */
public abstract class SM4Engine {

    public static final int KEY_SIZE = GmSSLJNI.SM4_KEY_SIZE;

    public static final int BLOCK_SIZE = GmSSLJNI.SM4_BLOCK_SIZE;

    protected abstract void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random);

    protected abstract byte[] engineGetIV();

    protected abstract int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException;

    protected abstract int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException;

    protected abstract void engineUpdateAAD(byte[] src, int offset, int len);

    //String getAlgorithmName();

    //int getBlockSize();
}
