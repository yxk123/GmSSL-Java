package org.gmssl.crypto.asymmetric;

import org.gmssl.GmSSLJNI;

import java.security.spec.AlgorithmParameterSpec;

/**
 * @author yongfeili
 * @date 2024/8/21
 * @description
 */
public class SM9EncMasterKeyGenParameterSpec implements AlgorithmParameterSpec {

    private String id;

    protected SM9EncMasterKeyGenParameterSpec() {

    }

    public SM9EncMasterKeyGenParameterSpec(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }
}

