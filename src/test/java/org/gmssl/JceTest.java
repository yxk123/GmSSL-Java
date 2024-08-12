package org.gmssl;

import org.gmssl.crypto.SM2PrivateKey;
import org.gmssl.crypto.SM2PublicKey;

import javax.crypto.Cipher;
import javax.crypto.spec.PBEParameterSpec;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;

/**
 * @author yongfeili
 * @date 2024/8/2
 * @description you must need to use openjdk!
 * https://jdk.java.net/archive/
 * https://stackoverflow.com/questions/1756801/how-to-sign-a-custom-jce-security-provider
 */
public class JceTest {

    public static void main(String[] args) {
        // 动态添加提供者
        Security.addProvider(new org.gmssl.crypto.GmSSLProvider());
        SM2Test();

    }

    public static void SM2Test() {
        // 尝试获取Cipher实例
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("SM2", "GmSSL");
            keyPairGen.initialize(256);
            KeyPair keyPair = keyPairGen.generateKeyPair();
            byte[] pub= keyPair.getPublic().getEncoded();
            System.out.println(byteToHex(pub));
            byte[] pri= keyPair.getPrivate().getEncoded();
            System.out.println(byteToHex(pri));

            Cipher cipher = Cipher.getInstance("SM2", "GmSSL");
            // 测试加密
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            byte[] plaintext = "Hello, GmSSL".getBytes();
            byte[] ciphertext = cipher.doFinal(plaintext);
            System.out.println("Ciphertext: " + byteToHex(ciphertext));
            // 测试解密
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] decrypted = cipher.doFinal(ciphertext);
            System.out.println("Decrypted: " + new String(decrypted));

            // 测试签名验签
            Signature signature = Signature.getInstance("SM2", "GmSSL");
            // 测试签名
            signature.initSign(keyPair.getPrivate());
            byte[] signatureText = "Hello, GmSSL".getBytes();
            signature.update(signatureText);
            byte[] signatureByte = signature.sign();
            System.out.println("Signature:"+byteToHex(signatureByte));
            // 测试验签
            signature.initVerify(keyPair.getPublic());
            signature.update(signatureText);
            boolean signatureResult = signature.verify(signatureByte);
            System.out.println("SignatureResult:"+signatureResult);

            //测试导入私钥公钥签名验签
            Signature signatureImport = Signature.getInstance("SM2", "GmSSL");
            // 测试导入私钥
            String privateKeyInfoHex="308193020100301306072a8648ce3d020106082a811ccf5501822d0479307702010104207fef3e258348873c47117c15093266e9dad99e131f1778e53d362b2b70649f85a00a06082a811ccf5501822da14403420004f94c0abb6cd00c6f0918cb9c54162213501d5cc278f5d3fcf63886f4e1dc6322b1b110e33a25216f258c4cce5fd52ab320d3b086ee5390f7387218c92578c3ab";
            byte[] privateKeyInfo = hexToByte(privateKeyInfoHex);
            signatureImport.initSign(new SM2PrivateKey(privateKeyInfo));
            signatureImport.update(signatureText);
            byte[] signatureByteImport = signatureImport.sign();
            System.out.println("Signature:"+byteToHex(signatureByteImport));
            // 测试导入公钥
            String publicKeyInfoHex = "3059301306072a8648ce3d020106082a811ccf5501822d03420004f94c0abb6cd00c6f0918cb9c54162213501d5cc278f5d3fcf63886f4e1dc6322b1b110e33a25216f258c4cce5fd52ab320d3b086ee5390f7387218c92578c3ab";
            byte[] publicKeyInfo = hexToByte(publicKeyInfoHex);
            signatureImport.initVerify(new SM2PublicKey(publicKeyInfo));
            signatureImport.update(signatureText);
            boolean signatureResultImport = signatureImport.verify(signatureByteImport);
            System.out.println("SignatureResult:"+signatureResultImport);
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
