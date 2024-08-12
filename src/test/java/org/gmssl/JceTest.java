package org.gmssl;

import org.gmssl.crypto.asymmetric.SM2PrivateKey;
import org.gmssl.crypto.asymmetric.SM2PublicKey;
import org.gmssl.crypto.digest.SM3Pbkdf2;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;

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
        //SM2Test();
        //SM3Test();
        SM4Test();
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

            //测试“Z值”哈希值
            SM2PublicKey sm2PublicKey = new SM2PublicKey(pub);
            byte[] zHash = sm2PublicKey.computeZ("Hello, GmSSL");
            System.out.println("zHash："+byteToHex(zHash));

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

    public static void SM3Test() {
        try {
            String text="Hello, GmSSL";
            //测试SM3哈希
            MessageDigest sm3Digest = MessageDigest.getInstance("SM3","GmSSL");
            sm3Digest.update("abc".getBytes());
            byte[] digest = sm3Digest.digest();
            sm3Digest.reset();
            sm3Digest.update(text.getBytes());
            System.out.println("digest:"+byteToHex(digest));

            //基于SM3的HMAC消息认证码算法
            Mac hmac = Mac.getInstance("SM3Hmac", "GmSSL");
            hmac.init(new SecretKeySpec(new Random().randBytes(Sm3Hmac.MAC_SIZE), "SM3Hmac"));
            hmac.update(text.getBytes());
            byte[] hmacFinal = hmac.doFinal();
            System.out.println("hmac:"+byteToHex(hmacFinal));

            //基于口令的密钥导出函数PBKDF2
            char[] password = "P@ssw0rd".toCharArray();
            byte[] salt = new Random().randBytes(SM3Pbkdf2.DEFAULT_SALT_SIZE);
            int iterations = SM3Pbkdf2.MIN_ITER * 2;
            int keyLength = SM3Pbkdf2.MAX_KEY_SIZE;
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("SM3Pbkdf2");
            SecretKey key = skf.generateSecret(spec);
            byte[] keyBytes = key.getEncoded();
            System.out.println("DerivedKey: " + byteToHex(keyBytes));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void SM4Test() {
        try {
            SecureRandom secureRandom = SecureRandom.getInstance("Random", "GmSSL");
            byte[] randomBytes = new byte[32];
            secureRandom.nextBytes(randomBytes);
            System.out.println("Generated Random Bytes: " + byteToHex(randomBytes));

            Cipher sm4Cipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", "GmSSL");


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
