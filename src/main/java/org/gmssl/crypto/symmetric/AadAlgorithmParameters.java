package org.gmssl.crypto.symmetric;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * @author yongfeili
 * @date 2024/8/14
 * @description
 */

public class AadAlgorithmParameters extends GCMParameterSpec {

    protected byte[] aad;

    public AadAlgorithmParameters(int tLen, byte[] iv) {
        super(tLen, iv);
    }

    public AadAlgorithmParameters(int tLen, byte[] iv,byte[] aad) {
        super(tLen, iv);
        this.aad = aad;
    }

    public byte[] getAad() {
        return aad;
    }

    public void setAad(byte[] aad) {
        this.aad = aad;
    }
}
