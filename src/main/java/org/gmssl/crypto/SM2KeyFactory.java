package org.gmssl.crypto;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * @author yongfeili
 * @date 2024/8/2
 * @description
 */
public class SM2KeyFactory extends KeyFactorySpi {

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        // 实现生成公钥

        return null;
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        // 实现生成私钥
        return null;
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
        // 实现根据 Key 和 KeySpec 类型返回相应的 KeySpec
        return null;
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        // 实现将 Key 转换为本地的 SM2Key
        return null;
    }
}
