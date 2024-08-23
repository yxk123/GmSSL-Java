package org.gmssl;

import org.gmssl.crypto.asymmetric.*;
import org.gmssl.crypto.digest.SM3Pbkdf2;
import org.gmssl.crypto.symmetric.*;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;

/**
 * @author yongfeili
 * @date 2024/8/2
 * @description you must need to use openjdk!
 * https://jdk.java.net/archive/
 * https://stackoverflow.com/questions/1756801/how-to-sign-a-custom-jce-security-provider
 */
public class JceTest {

    @Before
    public void beforeTest(){
        Security.addProvider(new org.gmssl.crypto.GmSSLProvider());
    }

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        // 动态添加提供者
        Security.addProvider(new org.gmssl.crypto.GmSSLProvider());
        SM2Test();
        //SM3Test();
        //SM4Test();
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

    @Test
    public void SM4_CBC_test() throws Exception{
            String text="Hello, GmSSL";
            SecureRandom secureRandom = SecureRandom.getInstance("Random", "GmSSL");
            byte[] randomBytes = new byte[32];
            secureRandom.nextBytes(randomBytes);
            System.out.println("Generated Random Bytes: " + byteToHex(randomBytes));

            /*// 测试SM4加密，固定16个长度
            Cipher sm4Cipher = Cipher.getInstance("SM4", "GmSSL");
            SecretKeySpec sm4Key = new SecretKeySpec(secureRandom.generateSeed(SM4.KEY_SIZE), "SM4");
            sm4Cipher.init(Cipher.ENCRYPT_MODE, sm4Key);
            sm4Cipher.update("87654321".getBytes(),0, 8);
            byte[] ciphertext = sm4Cipher.doFinal("12345678".getBytes(), 0, 8);
            System.out.println("Ciphertext: " + byteToHex(ciphertext));
            // 测试SM4解密
            sm4Cipher.init(Cipher.DECRYPT_MODE, sm4Key);
            byte[] plaintext = sm4Cipher.doFinal(ciphertext, 0, 16);
            System.out.println("plaintext: " + new String(plaintext));*/

            Cipher sm4cbcCipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", "GmSSL");
            byte[] key = secureRandom.generateSeed(SM4CBC.KEY_SIZE);
            byte[] iv = secureRandom.generateSeed(SM4CBC.IV_SIZE);
            sm4cbcCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "SM4"), new IvParameterSpec(iv));
            byte[] plaintext = ("text:"+text).getBytes();
            int inputOffset = "text:".getBytes().length;
            int inputLen = plaintext.length - inputOffset;
            byte[] ciphertext = new byte[inputLen+SM4CBC.BLOCK_SIZE];
            //int test= sm4cbcCipher.update("abc".getBytes(), 0, 3, ciphertext, 0);
            int cipherlen = sm4cbcCipher.doFinal(plaintext, inputOffset, inputLen,ciphertext, 0);
            byte[] ciphertext1 = Arrays.copyOfRange(ciphertext,0,cipherlen);
            System.out.println("Ciphertext: " + byteToHex(ciphertext1));

            sm4cbcCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "SM4"), new IvParameterSpec(iv));
            byte[] plaintext1 = new byte[ciphertext1.length + SM4CBC.BLOCK_SIZE];
            int decryptedLen = sm4cbcCipher.doFinal(ciphertext1, 0,ciphertext1.length, plaintext1,0);
            byte[] plaintext2 =Arrays.copyOfRange(plaintext1,0,decryptedLen);
            String plaintextStr=new String(plaintext2);
            System.out.println("plaintext: " + plaintextStr);
    }

    @Test
    public void SM4_CTR_test() throws Exception{
            SecureRandom secureRandom = SecureRandom.getInstance("Random", "GmSSL");
            Cipher sm4Cipher = Cipher.getInstance("SM4/CTR/NoPadding", "GmSSL");
            byte[] key = secureRandom.generateSeed(SM4CTR.KEY_SIZE);
            byte[] iv = secureRandom.generateSeed(SM4CTR.IV_SIZE);
            sm4Cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "SM4"), new IvParameterSpec(iv));
            byte[] ciphertext = new byte[64];
            sm4Cipher.update("abc".getBytes(), 0, "abc".length(), ciphertext, 0);
            sm4Cipher.update("12345678".getBytes(), 0, "12345678".length(), ciphertext, 0);
            sm4Cipher.update("xxyyyzzz".getBytes(), 0, "xxyyyzzz".length(), ciphertext, 0);
            int cipherlen = sm4Cipher.doFinal("gmssl".getBytes(), 0, "gmssl".length(), ciphertext, 0);
            byte[] ciphertext1 = Arrays.copyOfRange(ciphertext,0,cipherlen);
            System.out.println("Ciphertext: " + byteToHex(ciphertext1));

            byte[] plaintext = new byte[64];
            sm4Cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "SM4"), new IvParameterSpec(iv));
            int plainlen = sm4Cipher.doFinal(ciphertext, 0, cipherlen, plaintext, 0);
            byte[] plaintext1 = Arrays.copyOfRange(plaintext,0,plainlen);
            System.out.println("plaintext: " + new String(plaintext1));
    }

    @Test
    public void SM4_GCM_test() throws Exception {
        String text="Hello, GmSSL";
        SecureRandom secureRandom = SecureRandom.getInstance("Random", "GmSSL");
        Cipher sm4Cipher = Cipher.getInstance("SM4/GCM/ZeroPadding", "GmSSL");
        byte[] key = secureRandom.generateSeed(SM4GCM.KEY_SIZE);
        byte[] iv = secureRandom.generateSeed(SM4GCM.DEFAULT_IV_SIZE);
        byte[] aad = "Hello: ".getBytes();
        sm4Cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "SM4"), new GCMParameterSpec(SM4GCM.MAX_TAG_SIZE,iv));
        sm4Cipher.updateAAD(aad);
        byte[] ciphertext = new byte[64];
        int cipherlen = sm4Cipher.doFinal(text.getBytes(), 0, text.getBytes().length, ciphertext, 0);
        System.out.println("Ciphertext: " + byteToHex(ciphertext));

        byte[] plaintext = new byte[64];
        sm4Cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "SM4"), new GCMParameterSpec(SM4GCM.MAX_TAG_SIZE,iv));
        sm4Cipher.updateAAD(aad);
        int plainlen =sm4Cipher.doFinal(ciphertext, 0, cipherlen, plaintext, 0);
        byte[] plaintext1 = Arrays.copyOfRange(plaintext,0,plainlen);
        System.out.println("plaintext: " + new String(plaintext1));
    }

    @Test
    public void SM9_cipher_test() throws Exception{
        String text="Hello, GmSSL";
        SM9EncMasterKeyGenParameterSpec sm9EncMasterKeyGenParameterSpec = new SM9EncMasterKeyGenParameterSpec("bob");
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("SM9", "GmSSL");
        keyPairGen.initialize(sm9EncMasterKeyGenParameterSpec);
        keyPairGen.generateKeyPair();

        PublicKey publicKey = keyPairGen.genKeyPair().getPublic();
        Cipher sm9Cipher = Cipher.getInstance("SM9", "GmSSL");
        sm9Cipher.init(Cipher.ENCRYPT_MODE, publicKey,sm9EncMasterKeyGenParameterSpec);
        byte[] ciphertext = sm9Cipher.doFinal(text.getBytes());
        System.out.println("Ciphertext: " + byteToHex(ciphertext));

        SM9PrivateKey privateKey= (SM9PrivateKey) keyPairGen.genKeyPair().getPrivate();
        SM9MasterKey masterKey = (SM9MasterKey)privateKey.getSecretKey();
        SM9UserKey userKey= masterKey.extractKey(sm9EncMasterKeyGenParameterSpec.getId());
        sm9Cipher.init(Cipher.DECRYPT_MODE, userKey.getPrivateKey());
        byte[] plaintext = sm9Cipher.doFinal(ciphertext);
        System.out.println("plaintext: " + new String(plaintext));
    }

    @Test
    public void SM9_sign_test() throws Exception{
        String text="Hello, GmSSL";
        SM9SignMasterKeyGenParameterSpec sm9SignMasterKeyGenParameterSpec = new SM9SignMasterKeyGenParameterSpec("alice");
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("SM9", "GmSSL");
        keyPairGen.initialize(sm9SignMasterKeyGenParameterSpec);
        keyPairGen.generateKeyPair();

        Signature signature = Signature.getInstance("SM9", "GmSSL");
        // 测试签名
        SM9PrivateKey privateKey= (SM9PrivateKey) keyPairGen.genKeyPair().getPrivate();
        SM9MasterKey masterKey = (SM9MasterKey)privateKey.getSecretKey();
        SM9UserKey userKey= masterKey.extractKey(sm9SignMasterKeyGenParameterSpec.getId());
        signature.initSign(userKey.getPrivateKey());
        byte[] signatureText = text.getBytes();
        signature.update(signatureText);
        byte[] signatureByte = signature.sign();
        System.out.println("Signature:"+byteToHex(signatureByte));
        // 测试验签
        signature.setParameter(sm9SignMasterKeyGenParameterSpec);
        PublicKey publicKey=  keyPairGen.genKeyPair().getPublic();
        signature.initVerify(publicKey);
        signature.update(signatureText);
        boolean signatureResult = signature.verify(signatureByte);
        System.out.println("SignatureResult:"+signatureResult);
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
