package org.gmssl.crypto.asymmetric;

import org.gmssl.GmSSLException;
import org.gmssl.Sm9EncMasterKey;

import javax.crypto.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author yongfeili
 * @date 2024/8/21
 * @description
 */
public class SM9Cipher extends CipherSpi {

    private int opmode;

    private Key key;

    private ByteBuffer buffer;

    private String id;

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {

    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {

    }

    @Override
    protected int engineGetBlockSize() {
        return 0;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return 0;
    }

    @Override
    protected byte[] engineGetIV() {
        return new byte[0];
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        /*if (!(key instanceof SM9PublicKey) || !(key instanceof SM9PrivateKey)) {
            throw new GmSSLException("Invalid key type");
        }*/
        this.opmode = opmode;
        this.key = key;
        SM9PrivateKey privateKey = (SM9PrivateKey)key;
        SM9UserKey userKey = (SM9UserKey)privateKey.getSecretKey();
        this.id = userKey.getId();
        // 初始化缓冲区
        this.buffer = ByteBuffer.allocate(2048);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        /*if (!(key instanceof SM9PublicKey) || !(key instanceof SM9PrivateKey)) {
            throw new GmSSLException("Invalid key type");
        }*/
        this.opmode = opmode;
        this.key = key;
        this.id = ((SM9EncMasterKeyGenParameterSpec)params).getId();
        // 初始化缓冲区
        this.buffer = ByteBuffer.allocate(2048);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        throw new GmSSLException("params should not be null!");
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
        buffer.clear();

        if (opmode == Cipher.ENCRYPT_MODE) {
            return encrypt(data);
        } else if (opmode == Cipher.DECRYPT_MODE) {
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

    private byte[] encrypt(byte[] plaintext) {
        SM9PublicKey encMasterKey = (SM9PublicKey) key;
        byte[] ciphertext = encMasterKey.encrypt(plaintext,id);
        return ciphertext;
    }

    private byte[] decrypt(byte[] ciphertext) {
        SM9PrivateKey privateKey = (SM9PrivateKey)key;
        byte[] plaintext = privateKey.decrypt(ciphertext);
        return plaintext;
    }
}
