package org.gmssl.crypto.asymmetric;

import org.gmssl.GmSSLException;
import org.gmssl.GmSSLJNI;
import org.gmssl.Sm9SignMasterKey;

/**
 * @author yongfeili
 * @date 2024/8/20
 * @description
 */
public class SM9SignMasterKey extends SM9MasterKey{

    public SM9SignMasterKey(){
        publicKey = new SM9SignPublicKey();
        privateKey = new SM9SignPrivateKey();
    }

    class SM9SignPublicKey extends SM9PublicKey {
        public long getPublicKey() {
            if (master_key == 0) {
                throw new GmSSLException("");
            }
            return master_key;
        }

        public void importPublicKeyPem(String file) {
            if (master_key != 0) {
                GmSSLJNI.sm9_sign_master_key_free(master_key);
            }
            if ((master_key = GmSSLJNI.sm9_sign_master_public_key_from_pem(file)) == 0) {
                throw new GmSSLException("");
            }
            has_private_key = false;
        }

        public void exportPublicKeyPem(String file) {
            if (master_key == 0) {
                throw new GmSSLException("");
            }
            if (GmSSLJNI.sm9_sign_master_public_key_to_pem(master_key, file) != 1) {
                throw new GmSSLException("");
            }
        }

        public Boolean verify(byte[] signature, String id,long sm9_sign_ctx) {
            int ret;
            ret = GmSSLJNI.sm9_verify_finish(sm9_sign_ctx, signature, master_key, id);
            if (ret == 1) {
                return true;
            } else {
                return false;
            }
        }

    }

    class SM9SignPrivateKey extends SM9PrivateKey{
        public void importEncryptedPrivateKeyInfoPem(String pass, String file) {
            if (master_key != 0) {
                GmSSLJNI.sm9_sign_master_key_free(master_key);
            }
            if ((master_key = GmSSLJNI.sm9_sign_master_key_info_decrypt_from_pem(pass, file)) == 0) {
                throw new GmSSLException("");
            }
            has_private_key = true;
        }

        public void exportEncryptedPrivateKeyInfoPem(String pass, String file) {
            if (master_key == 0) {
                throw new GmSSLException("");
            }
            if (has_private_key == false) {
                throw new GmSSLException("");
            }
            if (GmSSLJNI.sm9_sign_master_key_info_encrypt_to_pem(master_key, pass, file) != 1) {
                throw new GmSSLException("");
            }
        }

        public SM9SignMasterKey getOuterKey() {
            return SM9SignMasterKey.this;
        }

    }
    public void generateMasterKey() {
        if (this.master_key != 0) {
            GmSSLJNI.sm9_sign_master_key_free(this.master_key);
        }
        if ((this.master_key = GmSSLJNI.sm9_sign_master_key_generate()) == 0) {
            throw new GmSSLException("");
        }
        this.has_private_key = true;
    }

    public long getOuterKey() {
        if (this.master_key == 0) {
            throw new GmSSLException("");
        }
        if (this.has_private_key == false) {
            throw new GmSSLException("");
        }
        return this.master_key;
    }

    public SM9UserKey extractKey(String id) {
        if (this.master_key == 0) {
            throw new GmSSLException("");
        }
        if (this.has_private_key == false) {
            throw new GmSSLException("");
        }
        long key;
        if ((key = GmSSLJNI.sm9_sign_master_key_extract_key(this.master_key, id)) == 0) {
            throw new GmSSLException("");
        }
        return new SM9SignUserKey(key, id);
    }

}
