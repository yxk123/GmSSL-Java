package org.gmssl.crypto.symmetric;

import org.gmssl.GmSSLException;
import org.gmssl.GmSSLJNI;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author yongfeili
 * @date 2024/8/26
 * @description
 */
public class ZucCipher extends CipherSpi {

    public final static int IV_SIZE = GmSSLJNI.ZUC_IV_SIZE;
    public final static int BLOCK_SIZE = 4;

    private long zuc_ctx;
    private boolean inited;

    private byte[] iv;

    private int offset;

    public ZucCipher(){
        ctx();
    }

    @Override
    protected void engineSetMode(String mode){
        // ZUC 是流密码算法，不支持 ECB、CBC 等模式
    }

    @Override
    protected void engineSetPadding(String padding){
        // ZUC 是流密码算法，不需要填充
        if (!"NoPadding".equalsIgnoreCase(padding)) {
            throw new GmSSLException("Unsupported padding: " + padding);
        }
    }

    @Override
    protected int engineGetBlockSize() {
        // ZUC 是流密码算法，没有固定的块大小
        return 0;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        // 输出大小与输入大小相同
        return inputLen;
    }

    @Override
    protected byte[] engineGetIV() {
        return iv;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {

    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params instanceof IvParameterSpec) {
            IvParameterSpec ivSpec = (IvParameterSpec) params;
            this.iv = ivSpec.getIV();
        } else {
            throw new InvalidAlgorithmParameterException("Unsupported parameters");
        }
        init(key.getEncoded(), iv);
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
        int outLen = update(input, inputOffset, inputLen, output, outputOffset);
        this.offset+=outLen;
        return outLen;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        return new byte[0];
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        this.engineUpdate(input, inputOffset, inputLen, output, outputOffset);
        int outLen = doFinal(output, this.offset);
        outLen = outLen + this.offset;
        this.offset = 0;
        return outLen;
    }

    private void ctx(){
        if ((this.zuc_ctx = GmSSLJNI.zuc_ctx_new()) == 0) {
            throw new GmSSLException("");
        }
        this.inited = false;
    }

    private void init(byte[] key, byte[] iv){
        if (key == null
                || key.length != ZucKey.KEY_SIZE
                || iv == null
                || iv.length != this.IV_SIZE) {
            throw new GmSSLException("");
        }

        if (GmSSLJNI.zuc_encrypt_init(this.zuc_ctx, key, iv) != 1) {
            throw new GmSSLException("");
        }

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
        if ((outlen = GmSSLJNI.zuc_encrypt_update(this.zuc_ctx, in, in_offset, inlen, out, out_offset)) < 0) {
            throw new GmSSLException("");
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
        if ((outlen = GmSSLJNI.zuc_encrypt_finish(this.zuc_ctx, out, out_offset)) < 0) {
            throw new GmSSLException("");
        }

        this.inited = false;
        return outlen;
    }
}
