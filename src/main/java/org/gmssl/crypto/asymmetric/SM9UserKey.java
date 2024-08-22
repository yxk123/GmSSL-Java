package org.gmssl.crypto.asymmetric;

import java.security.spec.KeySpec;

/**
 * @author yongfeili
 * @date 2024/8/20
 * @description
 */
public abstract class SM9UserKey implements KeySpec {

    protected long sm9_key;

    protected String id;

    protected SM9PrivateKey privateKey;

    protected SM9UserKey(long key, String id) {
        this.sm9_key = key;
        this.id = id;
    }

    public String getId() {
        return this.id;
    }

    public SM9PrivateKey getPrivateKey() {
        return this.privateKey;
    }
}
