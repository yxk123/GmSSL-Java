package org.gmssl.crypto.symmetric;

import java.security.NoSuchAlgorithmException;

/**
 * @author yongfeili
 * @date 2024/8/13
 * @description
 */
public class SM4CipherFactory {

    public static SM4Engine createCipher(String mode){
        SM4Engine cipher;
        try {
            switch (mode.toUpperCase()) {
                case "ECB":
                    cipher = new SM4ECB();
                    break;
                case "CBC":
                    cipher = new SM4CBC();
                    break;
                case "CTR":
                    cipher = new SM4CTR();
                    break;
                case "GCM":
                    cipher = new SM4GCM();
                    break;
                default:
                    throw new NoSuchAlgorithmException("Unsupported mode: " + mode);
            }
        }catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return cipher;
    }

}
