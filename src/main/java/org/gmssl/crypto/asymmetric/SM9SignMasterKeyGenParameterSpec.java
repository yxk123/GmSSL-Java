package org.gmssl.crypto.asymmetric;

import java.security.spec.AlgorithmParameterSpec;

/**
 * @author yongfeili
 * @date 2024/8/21
 * @description
 */
public class SM9SignMasterKeyGenParameterSpec implements AlgorithmParameterSpec {

    private String id;

    protected SM9SignMasterKeyGenParameterSpec() {

    }

    public SM9SignMasterKeyGenParameterSpec(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }
}
