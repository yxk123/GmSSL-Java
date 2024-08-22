package org.gmssl.crypto.asymmetric;

import java.security.Key;
import java.security.spec.KeySpec;

/**
 * @author yongfeili
 * @date 2024/8/20
 * @description
 */
public abstract class SM9MasterKey implements KeySpec {

    protected long master_key;

    protected boolean has_private_key;

    public SM9PublicKey publicKey;

    public SM9PrivateKey privateKey;

    public abstract void generateMasterKey();

    public abstract long getOuterKey();

    public abstract SM9UserKey extractKey(String id);

}
