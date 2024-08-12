package org.gmssl.crypto.symmetric;

import org.gmssl.GmSSLException;
import org.gmssl.GmSSLJNI;

import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author yongfeili
 * @date 2024/8/12
 * @description
 */
public class SM4Cbc extends SM4Cipher{

    public final static int IV_SIZE = GmSSLJNI.SM4_BLOCK_SIZE;

    private long sm4_cbc_ctx = 0;

    private byte[] iv;

    public SM4Cbc() {
        super();
    }

    @Override
    protected byte[] engineGetIV() {
        return iv;
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (!(params instanceof IvParameterSpec)) {
            throw new GmSSLException("need the IvParameterSpec parameter");
        }
        this.iv = ((IvParameterSpec) params).getIV();

    }
}
