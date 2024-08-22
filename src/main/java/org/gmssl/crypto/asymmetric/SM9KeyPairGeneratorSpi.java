package org.gmssl.crypto.asymmetric;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;

/**
 * @author yongfeili
 * @date 2024/8/20
 * @description
 */
public class SM9KeyPairGeneratorSpi extends KeyPairGeneratorSpi {

    private SM9MasterKey masterKey;

    @Override
    public void initialize(int keysize, SecureRandom random) {

    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        if (params == null) {
            throw new InvalidAlgorithmParameterException("The parameter must not be null");
        }
        if (params instanceof SM9SignMasterKeyGenParameterSpec) {
            SM9SignMasterKeyGenParameterSpec spec = (SM9SignMasterKeyGenParameterSpec) params;
            this.masterKey = new SM9SignMasterKey();
        } else if (params instanceof SM9EncMasterKeyGenParameterSpec) {
            SM9EncMasterKeyGenParameterSpec spec = (SM9EncMasterKeyGenParameterSpec) params;
            this.masterKey = new SM9EncMasterKey();
        } else {
           throw new InvalidAlgorithmParameterException("");
        }
        masterKey.generateMasterKey();
    }

    @Override
    public KeyPair generateKeyPair() {
        return new KeyPair(masterKey.publicKey, masterKey.privateKey);
    }

}
