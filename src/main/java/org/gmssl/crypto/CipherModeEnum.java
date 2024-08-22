package org.gmssl.crypto;

/**
 * @author yongfeili
 * @date 2024/8/12
 * @description
 */
public enum CipherModeEnum {
    NONE,
    /**
     * Cipher Block Chaining
     */
    CBC,
    /**
     * Grinding Cycle Monitor
     */
    GCM,
    /**
     *
     */
    CTR,
    /**
     *
     */
    ECB;

}
