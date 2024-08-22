package org.gmssl.crypto;

/**
 * @author yongfeili
 * @date 2024/8/13
 * @description
 */
public interface PaddingScheme {

    String getPaddingName();

    int addPadding(byte[] in, int inOff);

    int padCount(byte[] in);
}
