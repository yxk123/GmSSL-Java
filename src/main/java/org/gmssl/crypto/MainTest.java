package org.gmssl.crypto;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;

/**
 * @author yongfeili
 * @date 2024/8/2
 * @description
 */
public class MainTest {

    public static void main(String[] args) {
        SM2Test();


    }

    public static void SM2Test() {
        // 动态添加提供者
        Security.addProvider(new org.gmssl.crypto.GmSSLProvider());

        // 打印所有已注册的提供者
        for (java.security.Provider provider : Security.getProviders()) {
            //System.out.println(provider.getName());
        }

        // 尝试获取Cipher实例
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("SM2", "GmSSL");
            keyPairGen.initialize(256);
            KeyPair keyPair = keyPairGen.generateKeyPair();
            byte[] pub= keyPair.getPublic().getEncoded();
            System.out.println(byteToHex(pub));
            byte[] pri= keyPair.getPrivate().getEncoded();
            System.out.println(byteToHex(pri));

            /*Cipher cipher = Cipher.getInstance("SM2", "GmSSLProvider");
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

            Signature signature = Signature.getInstance("SM2", "GmSSLProvider");
            signature.initSign(keyPair.getPrivate());*/
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * convert byte array to hex string
     * @param btArr
     * @return String
     */
    public static String byteToHex(byte[] btArr) {
        BigInteger bigInteger = new BigInteger(1, btArr);
        return bigInteger.toString(16);
    }

    /**
     * convert hex string to byte array
     * @param hexString
     * @return byte[]
     */
    public static byte[] hexToByte(String hexString) {
        byte[] byteArray = new BigInteger(hexString, 16)
                .toByteArray();
        if (byteArray[0] == 0) {
            byte[] output = new byte[byteArray.length - 1];
            System.arraycopy(
                    byteArray, 1, output,
                    0, output.length);
            return output;
        }
        return byteArray;
    }
}
