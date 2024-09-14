/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package org.gmssl.crypto.symmetric;

import java.security.NoSuchAlgorithmException;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/07/27
 * @description
 *
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
