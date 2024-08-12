package org.gmssl.crypto.digest;

import org.gmssl.GmSSLException;
import org.gmssl.GmSSLJNI;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * @author yongfeili
 * @date 2024/8/12
 * @description
 */
public class SM3Pbkdf2 extends SecretKeyFactorySpi {

    public final static int MAX_SALT_SIZE = GmSSLJNI.SM3_PBKDF2_MAX_SALT_SIZE;
    public final static int DEFAULT_SALT_SIZE = GmSSLJNI.SM3_PBKDF2_DEFAULT_SALT_SIZE;
    public final static int MIN_ITER = GmSSLJNI.SM3_PBKDF2_MIN_ITER;
    public final static int MAX_ITER = GmSSLJNI.SM3_PBKDF2_MAX_ITER;
    public final static int MAX_KEY_SIZE = GmSSLJNI.SM3_PBKDF2_MAX_KEY_SIZE;

    public final static String ALGORITHM = "SM3Pbkdf2";

    public SM3Pbkdf2() {
        super();
    }

    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
        if (!(keySpec instanceof PBEKeySpec)) {
            throw new GmSSLException("Invalid KeySpec");
        }
        PBEKeySpec pbeKeySpec = (PBEKeySpec) keySpec;
        char[] password = pbeKeySpec.getPassword();
        byte[] salt = pbeKeySpec.getSalt();
        int iterations = pbeKeySpec.getIterationCount();
        int derivedKeyLength = pbeKeySpec.getKeyLength();
        byte[] key = deriveKey(new String(password), salt, iterations, derivedKeyLength);
        return new SecretKeySpec(key, ALGORITHM);
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec) throws InvalidKeySpecException {
        throw new GmSSLException("Not supported");
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
        throw new GmSSLException("Not supported");
    }

    public byte[] deriveKey(String pass, byte[] salt, int iter, int keylen) {
        if (pass == null) {
            throw new GmSSLException("");
        }
        if (salt == null || salt.length > MAX_SALT_SIZE) {
            throw new GmSSLException("");
        }
        if (iter < MIN_ITER || iter > MAX_ITER) {
            throw new GmSSLException("");
        }
        if (keylen < 0 || keylen > MAX_KEY_SIZE) {
            throw new GmSSLException("");
        }
        byte[] key = GmSSLJNI.sm3_pbkdf2(pass, salt, iter, keylen);
        if (key == null) {
            throw new GmSSLException("");
        }
        return key;
    }
}
