package org.gmssl.crypto;

import org.gmssl.GmSSLException;
import org.gmssl.GmSSLJNI;

import java.security.PrivateKey;

/**
 * @author yongfeili
 * @date 2024/8/7
 * @description
 */
public class SM2PrivateKey extends SM2Key implements PrivateKey{

    public SM2PrivateKey() {
        super();
    }

    public SM2PrivateKey(byte[] der) {
        importPrivateKeyInfoDer(der);
    }

    public SM2PrivateKey(String password, String file) {
        importEncryptedPrivateKeyInfoPem(password, file);
    }

    public SM2PrivateKey(long sm2_key, boolean has_private_key) {
        super(sm2_key,has_private_key);
    }

    public String getAlgorithm() {
        return "SM2";
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return exportPrivateKeyInfoDer();
    }

    private void importPrivateKeyInfoDer(byte[] der) {
        if (der == null) {
            throw new GmSSLException("");
        }
        if (this.sm2_key != 0) {
            GmSSLJNI.sm2_key_free(this.sm2_key);
        }
        if ((this.sm2_key = GmSSLJNI.sm2_private_key_info_from_der(der)) == 0) {
            throw new GmSSLException("");
        }
        this.has_private_key = true;
    }

    private byte[] exportPrivateKeyInfoDer() {
        if (this.sm2_key == 0) {
            throw new GmSSLException("");
        }
        if (this.has_private_key == false) {
            throw new GmSSLException("");
        }
        byte[] der;
        if ((der = GmSSLJNI.sm2_private_key_info_to_der(this.sm2_key)) == null) {
            throw new GmSSLException("");
        }
        return der;
    }

    private void importEncryptedPrivateKeyInfoPem(String pass, String file) {
        if (this.sm2_key != 0) {
            GmSSLJNI.sm2_key_free(this.sm2_key);
        }
        if ((sm2_key = GmSSLJNI.sm2_private_key_info_decrypt_from_pem(pass, file)) == 0) {
            throw new GmSSLException("");
        }
        this.has_private_key = true;
    }

    public void exportEncryptedPrivateKeyInfoPem(String pass, String file) {
        if (this.sm2_key == 0) {
            throw new GmSSLException("");
        }
        if (this.has_private_key == false) {
            throw new GmSSLException("");
        }
        if (GmSSLJNI.sm2_private_key_info_encrypt_to_pem(this.sm2_key, pass, file) != 1) {
            throw new GmSSLException("");
        }
    }

}
