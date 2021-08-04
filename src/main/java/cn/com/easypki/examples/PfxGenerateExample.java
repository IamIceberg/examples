/**
 * Project: examples
 * Author: Iceberg
 * Create Time: 7/18/21
 * Email: 1515479701@qq.com
 */
package cn.com.easypki.examples;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;

/**
 * @author Iceberg
 * @since 1.0.11
 */
public class PfxGenerateExample {

    /**
     * 生成符合PKCS#12要求的PFX文件
     *
     * @param entityCertificate 实体公钥证书，不能为null
     * @param chain             实体公钥证书对应的证书链，不能为null
     * @param entityPrivateKey  实体公钥证书对应的私钥，不能为null
     * @param alias             别名，不能为null
     * @param pin               个人身份识别码(Personal Identification Number)，用于保护私钥
     * @return PFX的字节流
     * @throws KeyStoreException 如果生成PFX失败
     */
    public static byte[] generate(Certificate entityCertificate, Certificate[] chain, PrivateKey entityPrivateKey, String alias, String pin) throws KeyStoreException {

        if (null == entityCertificate) {
            throw new IllegalArgumentException("entity certificate must NOT bu null.");
        }
        if (null == entityCertificate) {
            throw new IllegalArgumentException("entity privateKey must NOT bu null.");
        }
        if (null == chain || chain.length < 1) {
            throw new IllegalArgumentException("certificate chain must NOT bu null.");
        }
        if (null == alias) {
            throw new IllegalArgumentException("alias must NOT bu null.");
        }

        ByteArrayOutputStream byteArrayOutputStream = null;
        byte[] pfxBinary = null;
        try {
            byteArrayOutputStream = new ByteArrayOutputStream();
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.setCertificateEntry(alias, entityCertificate);
            keyStore.setKeyEntry(alias, entityPrivateKey, pin.toCharArray(), chain);
            keyStore.store(byteArrayOutputStream, pin.toCharArray());

            pfxBinary = byteArrayOutputStream.toByteArray();
        } catch (Exception e) {
            throw new KeyStoreException("failed to generate PKCS#12 type pfx, cause:" + e.getMessage());
        } finally {
            if (null != byteArrayOutputStream) {
                try {
                    byteArrayOutputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        return pfxBinary;
    }
}
