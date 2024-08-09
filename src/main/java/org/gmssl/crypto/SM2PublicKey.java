package org.gmssl.crypto;

import org.gmssl.GmSSLException;
import org.gmssl.GmSSLJNI;

import java.security.PublicKey;

/**
 * @author yongfeili
 * @date 2024/8/7
 * @description
 */
public class SM2PublicKey extends SM2Key implements PublicKey{

    public SM2PublicKey() {
        super();
    }

    public SM2PublicKey(byte[] der) {
        importPublicKeyInfoDer(der);
    }

    public SM2PublicKey(String file) {
        importPublicKeyInfoPem(file);
    }

    public SM2PublicKey(long sm2_key, boolean has_private_key) {
        super(sm2_key,has_private_key);
    }

    @Override
    public String getAlgorithm() {
        return "SM2";
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return exportPublicKeyInfoDer();
    }

    private void importPublicKeyInfoDer(byte[] der) {
        if (der == null) {
            throw new GmSSLException("");
        }
        if (this.sm2_key != 0) {
            GmSSLJNI.sm2_key_free(this.sm2_key);
        }
        if ((this.sm2_key = GmSSLJNI.sm2_public_key_info_from_der(der)) == 0) {
            throw new GmSSLException("");
        }
        this.has_private_key = false;
    }

    private byte[] exportPublicKeyInfoDer() {
        if (this.sm2_key == 0) {
            throw new GmSSLException("");
        }
        byte[] der;
        if ((der = GmSSLJNI.sm2_public_key_info_to_der(this.sm2_key)) == null) {
            throw new GmSSLException("");
        }
        return der;
    }

    private void importPublicKeyInfoPem(String file) {
        if (this.sm2_key != 0) {
            GmSSLJNI.sm2_key_free(this.sm2_key);
        }
        if ((this.sm2_key = GmSSLJNI.sm2_public_key_info_from_pem(file)) == 0) {
            throw new GmSSLException("");
        }
        this.has_private_key = false;
    }

    public void exportPublicKeyInfoPem(String file) {
        if (this.sm2_key == 0) {
            throw new GmSSLException("");
        }
        if (GmSSLJNI.sm2_public_key_info_to_pem(this.sm2_key, file) != 1) {
            throw new GmSSLException("");
        }
    }

}
