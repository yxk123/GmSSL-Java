/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package org.gmssl.crypto;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/07/27
 * @description
 *
 */
public class PKCS7PaddingScheme implements PaddingScheme{
    @Override
    public String getPaddingName() {
        return null;
    }

    @Override
    public int addPadding(byte[] in, int inOff) {
        return 0;
    }

    @Override
    public int padCount(byte[] in) {
        return 0;
    }
}
