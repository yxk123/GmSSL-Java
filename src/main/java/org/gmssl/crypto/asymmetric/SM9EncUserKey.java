package org.gmssl.crypto.asymmetric;

import org.gmssl.GmSSLException;
import org.gmssl.GmSSLJNI;
import org.gmssl.Sm9SignKey;

/**
 * @author yongfeili
 * @date 2024/8/21
 * @description
 */
public class SM9EncUserKey extends SM9UserKey{
    protected SM9EncUserKey(long sm9_key, String id) {
        super(sm9_key, id);
        this.privateKey = new SM9EncPrivateKey();
    }

    class SM9EncPrivateKey extends SM9PrivateKey {
        public void importEncryptedPrivateKeyInfoPem(String pass, String file) {
            if (sm9_key != 0) {
                GmSSLJNI.sm9_enc_key_free(sm9_key);
            }
            if ((sm9_key = GmSSLJNI.sm9_enc_key_info_decrypt_from_pem(pass, file)) == 0) {
                throw new GmSSLException("");
            }
        }

        public void exportEncryptedPrivateKeyInfoPem(String pass, String file) {
            if (sm9_key == 0) {
                throw new GmSSLException("Key not initialized");
            }
            if (GmSSLJNI.sm9_enc_key_info_encrypt_to_pem(sm9_key, pass, file) != 1) {
                throw new GmSSLException("");
            }
        }

        public byte[] decrypt(byte[] ciphertext) {
            if (sm9_key == 0) {
                throw new GmSSLException("");
            }
            if (ciphertext == null) {
                throw new GmSSLException("");
            }

            byte[] plaintext;
            if ((plaintext = GmSSLJNI.sm9_decrypt(sm9_key, id, ciphertext)) == null) {
                throw new GmSSLException("");
            }
            return plaintext;
        }
        public SM9EncUserKey getOuterKey() {
            return SM9EncUserKey.this;
        }
    }

}
