package org.gmssl.crypto;

import java.security.*;

/**
 * @author yongfeili
 * @date 2024/8/2
 * @description
 */
public class SM2Signature extends SignatureSpi {

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
// 实现初始化验证
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        // 实现初始化签名
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
// 实现更新方法
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
// 实现更新方法
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        // 实现签名生成
        return new byte[0];
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        // 实现签名验证
        return false;
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
// 实现设置参数
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        // 实现获取参数
        return null;
    }
}
