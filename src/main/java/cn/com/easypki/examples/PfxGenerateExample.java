/**
 * Project: examples
 * Author: Iceberg
 * Create Time: 7/18/21
 * Email: 1515479701@qq.com
 */
package cn.com.easypki.examples;

import cn.unitid.easypki.util.CertificateConverter;

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

    final static String PRODUCT_CA = "MIIESTCCAzGgAwIBAgINAIGbEbvmtuLV7/9QsjANBgkqhkiG9w0BAQsFADCBnjELMAkGA1UEBhMCQ04xDzANBgNVBAgMBuaxn+iLjzEPMA0GA1UEBwwG5Y2X5LqsMS0wKwYDVQQKDCTmsZ/oi4/mmbrmhafmlbDlrZforqTor4HmnInpmZDlhazlj7gxLTArBgNVBAsMJOaxn+iLj+aZuuaFp+aVsOWtl+iupOivgeaciemZkOWFrOWPuDEPMA0GA1UEAwwGUk9PVENBMB4XDTIxMDUzMTE2MDAwMFoXDTMxMDUzMTE2MDAwMFowgcIxCzAJBgNVBAYTAkNOMRIwEAYDVQQIDAnmsZ/oi4/nnIExEjAQBgNVBAcMCeWNl+S6rOW4gjEtMCsGA1UECgwk5rGf6IuP5pm65oWn5pWw5a2X6K6k6K+B5pyJ6ZmQ5YWs5Y+4MS0wKwYDVQQLDCTmsZ/oi4/mmbrmhafmlbDlrZforqTor4HmnInpmZDlhazlj7gxLTArBgNVBAMMJOaxn+iLj+aZuuaFp+aVsOWtl+iupOivgeaciemZkOWFrOWPuDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKOxcnzt0hUlLHhaoViS0awMFL6pdPJ8oGdxqiOWlQ2mrzCokKVIT+iPPpjMn22CkqLQE2H/N22VZltqTdTkViyDOZ37BOvOe5+T9D6Gd/YkH17s1oSaw2NEOsjl3AKJVACCLKkzFCa7y87O62wOGcGnDq/9VTelK6JJXK9rUxgzmIBIb7O6/gkcyXySW9ech+FIuY8T1eOW/1bqyH0/tSVeCrP4nUhM/FJEQoFMuUGJ2KLjNOXQU1WrnWX1ALKZT+FZUHLcTLDw19WHV2YRvhDMDSSbD1MNfsS3drTtt3WBdVFBwDIeYmadF0r84OEstCuR/lNt9yRDX8DshrtQiKkCAwEAAaNgMF4wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQUaDEFjAWqrM/My95QUS893qZKCSIwHwYDVR0jBBgwFoAUm4DddM5orVtH3zbymN8ViqISWPIwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4IBAQAf0dVgkZGua8PKRrJZvRLGAp3FHYVyK70+tvnJ56wPnpxIC7mirbUfWjWgpY96tLIcb2fSLTAFkL9PbqTWBBpc2ugnm228c1m/ApCSNZPBOgSvg1SoquiobA6pP29HWaEH/vlHjkEz+heh8uew2icLFBZOsi6vjNFKYoDGR0NHEwRpQKDvZrWyElOdiEoF5s4DdqU0iSy3bv4tfyvql0XE2jA2LhSjbgdr95fpPyhBMdwB4lHS7BlDD/wy/NcpI9iFwFn0oWrqwZR4ao5O+Rn1jqzIW/y++Jo+X20BCLNMQMoreYzaREILN80U2nh94giF6G3xGUDWMHEDvS6FIKOo";
    final static String PRODUCT_ROOT = "MIIEJTCCAw2gAwIBAgINAMQOp0MeqfOlGULHCDANBgkqhkiG9w0BAQsFADCBnjELMAkGA1UEBhMCQ04xDzANBgNVBAgMBuaxn+iLjzEPMA0GA1UEBwwG5Y2X5LqsMS0wKwYDVQQKDCTmsZ/oi4/mmbrmhafmlbDlrZforqTor4HmnInpmZDlhazlj7gxLTArBgNVBAsMJOaxn+iLj+aZuuaFp+aVsOWtl+iupOivgeaciemZkOWFrOWPuDEPMA0GA1UEAwwGUk9PVENBMB4XDTIxMDUzMDE2MDAwMFoXDTMxMDUyODE2MDAwMFowgZ4xCzAJBgNVBAYTAkNOMQ8wDQYDVQQIDAbmsZ/oi48xDzANBgNVBAcMBuWNl+S6rDEtMCsGA1UECgwk5rGf6IuP5pm65oWn5pWw5a2X6K6k6K+B5pyJ6ZmQ5YWs5Y+4MS0wKwYDVQQLDCTmsZ/oi4/mmbrmhafmlbDlrZforqTor4HmnInpmZDlhazlj7gxDzANBgNVBAMMBlJPT1RDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMHxk0/KU2GUpTHv/XNcyQ7x4nay927gPQORSY1oD56snoLm+fkO8upTaFHIpONAdbzX1fIlyq3CWnzLKq+k3GMtFgvdVI/HX1OO3xWqHF++QmC4VCMoPCuI7poyeoSAbKluCvc5FrNLbHE/7ScgMPQIVwDC+9lXfWvuVlDTOOHnYYKvjJKffw6qQBz7deJoJy18YAXnsjsgICtRi9s6T8I1tO9Ge7bhlopWqzjkRDF7Y3WHUPbBFmnl+4BvSrebxOhKrlIv1t9E0ZhjWCOhUukoJlNwvy1oyk/OsgE+mK5OVobdzg501RUxfcrta3eK4RCbsBNf1O1DirZGhF+VAX8CAwEAAaNgMF4wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQUm4DddM5orVtH3zbymN8ViqISWPIwHwYDVR0jBBgwFoAUm4DddM5orVtH3zbymN8ViqISWPIwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4IBAQB/FkOIOBZ/BaCuR1ClQIQyMG7UhhNuIIqeTPpHOJZAKAjgcqKa9NyAz6a3WAUyiWggVTC+89QvQCswLaYfqU6ldYYWrr3BFTFJmFdSTRg7txgiYSPXsL42lbNgluzr2u61G426gbWQYIz+kvwUEdQnf4VZUIQTNvUotAHkMOFB0HoePVcH4N77g/XUnElby4blf85yQeLtZhfFFaAInyeODnqoP3CC0CN06p58sGvQLRHgm6xIhyY5ZMocIzK1ukqOOzqZVeAmJWSGx5N628THIw6HLYFvc8XEGvlUWXNCNBH5LBgKAeadmy+Sv9wXhiiDM9lRZDXNfDBWAQ7nzVi/";

    final static String TEST_RSA_CA = "MIIDkDCCAnigAwIBAgINAPWqZqBo38bWp+GusjANBgkqhkiG9w0BAQsFADBgMQswCQYDVQQGEwJDTjESMBAGA1UECAwJ5rGf6IuP55yBMRIwEAYDVQQHDAnljZfkuqzluIIxETAPBgNVBAoMCEFCQyBsdGQuMRYwFAYDVQQDDA10ZXN0UlNBUm9vdENBMB4XDTIxMDcyODA4MDMyNloXDTMxMDcyODA4MDMyNlowSTELMAkGA1UEBhMCQ04xEjAQBgNVBAgMCeaxn+iLj+ecgTESMBAGA1UEBwwJ5Y2X5Lqs5biCMRIwEAYDVQQDDAl0ZXN0UlNBQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCoYf6UHpng2vD8lnJCiaKyI84Ac8D9eQufSnj8zKkxkf7GluWGkobTH/DwRUCHQAmKknqxhsrB8BhWMM6Y7/HVisRmdfOYq4Ntbe/9XffBbiWtrM2uLrjMBebVoRLeTzJEEATmJ4kGrSazEgfdw4aoSECNJSV5cvdhyVM6fhQAQpjqIX1GXZPUAgRlW4ojDHrVoEfWpudF0Syj3K+v0fQLm55jTcX06W3V/YvjpwpgGLwLCytwdHGwPJpk4NVO1v0VRCOIKWpII+zM4tulaBkxJ2nyNkaXA8Kkb8D09Oiy3zQ7HdUPx5YuszJmRbQcmswvQnWx8IDXMkoB9rLZoUqjAgMBAAGjYDBeMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFBM5eQL/fwh11DijQV0ELA/6JUSdMB8GA1UdIwQYMBaAFDfYwrZXs9w0/nR61tbw9X6yOfAJMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAQEAPa1o5dnX6Bcc2TZpObds0GNIwQdhhmfj/a2zcLCjVyyFoci96AN/rbjrPyLsOOj/xbv8uL8DDYas8J1xnQ55zKBadYXO1PHuhWjmTC1Eq3Ak4HgJYN4It9B692o+gRhHBsIASFrhzdTgi+xd8ddebUoVgXsbpVraJSrHDm8vadV89ycOmLKhz5fXBnoFKtyTPKjJqaSlvZIWGsgs7Ujyfz7KvrY4sIq15kZ8uu2u552FA/u03CpIHsibRtoVDuI39FgnZ63GKe/Yz5SmJghDRWV/r3atUf4InxX7Xdy9XWXjptFDjaF8rhKQNxb0qb6lqLUKQqCvZyH0kiHdJN3Ouw==";
    final static String TEST_RSA_ROOT = "MIIDpzCCAo+gAwIBAgINAKslDbtJyUwaZ7B/WDANBgkqhkiG9w0BAQsFADBgMQswCQYDVQQGEwJDTjESMBAGA1UECAwJ5rGf6IuP55yBMRIwEAYDVQQHDAnljZfkuqzluIIxETAPBgNVBAoMCEFCQyBsdGQuMRYwFAYDVQQDDA10ZXN0UlNBUm9vdENBMB4XDTIxMDcyNjE2MDAwMFoXDTMxMDcyNDE2MDAwMFowYDELMAkGA1UEBhMCQ04xEjAQBgNVBAgMCeaxn+iLj+ecgTESMBAGA1UEBwwJ5Y2X5Lqs5biCMREwDwYDVQQKDAhBQkMgbHRkLjEWMBQGA1UEAwwNdGVzdFJTQVJvb3RDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK+pKjMfsfe7EFb1fAxrO5f7EfmkOWlQS+4VfRaQk7AGKYWTuKuiK/8CO657qXb59OnDCgFWONBaXnaAMSy2nu8TVmwgpscb78q/8A3ILZlmBv2vKkiFexljRguZsEWbFGs0ya4/mK86Xju+vELPkbtoFJy1RrAn4lXc9KWEcuxjfjl8sH8fDYK5YP2GuvdeaZTdb4qcYQgytLdFqVutp2RdomOJv7l6jQRLfHY9q0WcuiyoOW0w6ABy4SNPJOOjHZ6YmdFBR2ynQcQH/x/8VCKVMDBjwDho52lhS2HSPwzofshpEaOyRhTgSrvhZGRJh2D1r+jGCEAiZH0PFXT8U60CAwEAAaNgMF4wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQUN9jCtlez3DT+dHrW1vD1frI58AkwHwYDVR0jBBgwFoAUN9jCtlez3DT+dHrW1vD1frI58AkwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4IBAQAuuhRtOLsvEKrAHmw8goPnp9+Ap7mWkezWWcYVBdOkplWlZ8CTdBDnNkyBgSqSmYxCpP3V4LruMvHUgg3gFRlPznwAIr5Oaiqhc2eh7X2qOSnAo62RZ7re8LDfw8Ir5aMEHP0pl4dwgOJlVURqZH8f4f4LR/6ljm1yvKdki3KDa68QgG8fZ+dWsY95r2eCiK6PBXQydqeDklncQfMSKuG8PV1X/MOyhmTtM1JO4ZkN/bgyTrPx+bjpeaxnjO9Enis8czUibpjAGd7vDjtro5nfdIfYsBYxO7mo8wT4+0k4julR57GHvIrV57300E2uK8tP3g5Oy0iWYXDkUO+cqkAO";

    //final String TEST_SM2_CA = "MIICBDCCAaqgAwIBAgINAMMDt+7PyG6Kq093ajAKBggqgRzPVQGDdTBgMQswCQYDVQQGEwJDTjESMBAGA1UECAwJ5rGf6IuP55yBMRIwEAYDVQQHDAnljZfkuqzluIIxETAPBgNVBAoMCEFCQyBsdGQuMRYwFAYDVQQDDA10ZXN0U00yUm9vdENBMB4XDTIxMDcyODA4MDQxOFoXDTMxMDcyODA4MDQxOFowSTELMAkGA1UEBhMCQ04xEjAQBgNVBAgMCeaxn+iLj+ecgTESMBAGA1UEBwwJ5Y2X5Lqs5biCMRIwEAYDVQQDDAl0ZXN0U00yQ0EwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAASZn9V1+P2VMzpOu1j/zxrwu4KBB0WPnHsyjsYUWOx9X2ZmZjcFTUyS8quASseifdAYZD85nrJOX3qz4rvYTKRpo2AwXjAMBgNVHRMEBTADAQH/MB0GA1UdDgQWBBQTcZFDuLKDKvEWLGWUNnpKpY0mJzAfBgNVHSMEGDAWgBRnU/Ed5+LtEzdXXqsSqryXEJYubTAOBgNVHQ8BAf8EBAMCAYYwCgYIKoEcz1UBg3UDSAAwRQIgK29UBHeObl/oxWng1RPiLdDciUsvascyXxtllhQPzNYCIQCZ0WoBVacXIA4S2VJa3rbpMycU51/hGjwOzmZChiJfGQ==";
    //final String TEST_SM2_ROOT = "MIICGzCCAcGgAwIBAgINAOvu3NaAifr0KF9WQjAKBggqgRzPVQGDdTBgMQswCQYDVQQGEwJDTjESMBAGA1UECAwJ5rGf6IuP55yBMRIwEAYDVQQHDAnljZfkuqzluIIxETAPBgNVBAoMCEFCQyBsdGQuMRYwFAYDVQQDDA10ZXN0U00yUm9vdENBMB4XDTIxMDcyNjE2MDAwMFoXDTMxMDcyNDE2MDAwMFowYDELMAkGA1UEBhMCQ04xEjAQBgNVBAgMCeaxn+iLj+ecgTESMBAGA1UEBwwJ5Y2X5Lqs5biCMREwDwYDVQQKDAhBQkMgbHRkLjEWMBQGA1UEAwwNdGVzdFNNMlJvb3RDQTBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABF43svwjEXT0jpdblqyKBO0srsurZVkypu2srs1n7Fu3+WMPqjgfSMw2FxlsP1PMHGLC+KIPgxp74VtCIrYg7gajYDBeMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFGdT8R3n4u0TN1deqxKqvJcQli5tMB8GA1UdIwQYMBaAFGdT8R3n4u0TN1deqxKqvJcQli5tMA4GA1UdDwEB/wQEAwIBhjAKBggqgRzPVQGDdQNIADBFAiEAhUJSP/lA6sw+GeXN9b9yvHRKU7Vv98jW0ZVJvXKK7QMCIAZdQI8Le9rhZ4+4td4F5xseEpCarU6UVkAXRQiGMzba";

    static final int MODE = 0;

    final static Certificate[] chain;

    static {
        chain = new Certificate[2];
        Certificate ct = null;

        try {
            if (0 == MODE) {
                ct = CertificateConverter.fromBase64(TEST_RSA_CA);

            } else if (1 == MODE) {
                ct = CertificateConverter.fromBase64(PRODUCT_CA);
            } else {
                throw new Exception("invalid parameter MODE: " + MODE);
            }

            chain[1] = ct;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成符合PKCS#12要求的PFX文件
     *
     * @param entityCertificate 实体公钥证书，不能为null
     * @param entityPrivateKey  实体公钥证书对应的私钥，不能为null
     * @param alias             别名，不能为null
     * @param pin               个人身份识别码(Personal Identification Number)，用于保护私钥
     * @return PFX的字节流
     * @throws KeyStoreException 如果生成PFX失败
     */
    public static byte[] generate(Certificate entityCertificate, PrivateKey entityPrivateKey, String alias, String pin) throws KeyStoreException {

        if (null == entityCertificate) {
            throw new IllegalArgumentException("entity certificate must NOT bu null.");
        }
        if (null == entityPrivateKey) {
            throw new IllegalArgumentException("entity privateKey must NOT bu null.");
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
            chain[0] = entityCertificate;
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
