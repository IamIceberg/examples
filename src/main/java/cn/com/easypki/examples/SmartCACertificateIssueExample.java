/**
 * Project: examples
 * Author: Iceberg
 * Create Time: 7/19/21
 * Email: 1515479701@qq.com
 */
package cn.com.easypki.examples;

import cn.unitid.ca.sdk.constant.IdType;
import cn.unitid.ca.sdk.dto.cert.AgentInfo;
import cn.unitid.ca.sdk.dto.cert.PersonalSeniorCertificate;
import cn.unitid.ca.sdk.request.sop.personal.PersonalIssueRequest;
import cn.unitid.ca.sdk.response.sop.personal.PersonalIssueResponse;
import cn.unitid.ca.sdk.service.PersonalCertSopApi;
import cn.unitid.ca.sdk.service.impl.PersonalCertSopApiImpl;
import cn.unitid.easypki.util.CertificateConverter;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Before;
import org.junit.Test;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

/**
 * Smart CA 签发证书示例。
 * <p>
 * 参考文档及SDK下载地址：http://sdk.oss.smartcert.cn/v1/sdk/
 *
 * @author Iceberg
 * @since 1.0.11
 */
public class SmartCACertificateIssueExample {

    KeyPair userKeyPair = null;
    Certificate[] chain = null;

    private String caCertificate = null;

    /**
     * 初始化，生成RSA2048位算法的密钥对，用于生成PKCS10证书请求
     *
     * @throws Exception
     */
    @Before
    public void init() throws Exception {


        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        userKeyPair = keyPairGenerator.generateKeyPair();
    }

    /**
     * 生成PKCS10 证书请求
     *
     * @param subject 证书主题项，形如：CN=张三,OU=SmartCA,C=CN
     * @return Base64编码的PKCS10证书请求
     * @throws Exception
     */
    private String genPKCS10Request(String subject) throws Exception {
        X500Name x500Name = new X500Name(subject);
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(userKeyPair.getPublic().getEncoded());
        CertificationRequestInfo requestInfo = new CertificationRequestInfo(x500Name, publicKeyInfo, null);
        Signature signer = Signature.getInstance("SHA1WITHRSA");
        signer.initSign(userKeyPair.getPrivate());
        signer.update(requestInfo.getEncoded());
        byte[] signature = signer.sign();
        CertificationRequest certificationRequest = new CertificationRequest(requestInfo, new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.5"), DERNull.INSTANCE), new DERBitString(signature));

        return Base64.toBase64String(certificationRequest.getEncoded());
    }

    @Test
    public void testIssue() throws Exception {
        //身份证号码
        String id = "341102198611250812";
        //身份证姓名
        String name = "张三蓝12";
        //手机号码
        String phoneNumber = "18111111111";

        String ou = "SmartCA";
        //组织机构
        String o = "SmartCA";
        //城市
        String city = "合肥";
        //省份
        String province = "安徽";

        //国家必须为CN
        String c = "CN";

        //注意CN=的值和身份证姓名一致
        String subject = "CN=" + name + ",OU=" + ou + ",O=" + o + "L=" + city + ",ST=" + province + ",C=" + c;

        //构造证书请求
        String pkcs10 = this.genPKCS10Request(subject);

        //构造请求的证书模板
        PersonalSeniorCertificate certTemplate = new PersonalSeniorCertificate();
        certTemplate.setIdNumber(id);
        certTemplate.setIdType(IdType.ID);
        certTemplate.setCommonName(name);
        certTemplate.setOrganization(o);
        certTemplate.setCity(city);
        certTemplate.setProvince(province);
        certTemplate.setCountry(c);

        //证书申请者的经办人信息
        AgentInfo agent = new AgentInfo();
        agent.setAgentId(id);
        agent.setAgentName(name);
        agent.setAgentPhone(phoneNumber);

        //构造签发请求
        PersonalIssueRequest pir = new PersonalIssueRequest();
        pir.setPersonalSeniorCertificate(certTemplate);
        pir.setPkCS10(pkcs10);
        pir.setAgentInfo(agent);

        //使用客户App信息构造SDK接口的实例
        String url = "http://api.ca.demo.smartcert.cn/api";
        //您的appKey
        String appKey = "G4091mSF";
        //您的appSecret
        String secretKey = "SRSyaQMO";

        PersonalCertSopApi personalCertSopApi = new PersonalCertSopApiImpl(url, appKey, secretKey);

        PersonalIssueResponse personalIssueResponse = personalCertSopApi.issue(pir);

        //示例，后续业务处理。生产环境下应该注释掉。
        System.out.println("================================");
        System.out.println("响应内容:" + personalIssueResponse);
        System.out.println("================================");
        System.out.println("SDK请求ID:" + personalIssueResponse.getRequestId());
        System.out.println("SDK响应消息:" + personalIssueResponse.getMsg());
        System.out.println("SDK响应码:" + personalIssueResponse.getErrorCode());
        System.out.println("================================");
        if (null != personalIssueResponse.getData()) {
            System.out.println("证书ID:" + personalIssueResponse.getData().getCertId());
            System.out.println("加密证书:" + personalIssueResponse.getData().getEncryptionCert());
            System.out.println("加密证书私钥:" + personalIssueResponse.getData().getEncryptionPrivateKey());
            System.out.println("签名证书:" + personalIssueResponse.getData().getSignatureCert());
            System.out.println("业务响应码:" + personalIssueResponse.getData().getIncorrect());
            System.out.println("业务响应消息:" + personalIssueResponse.getData().getMessage());
        }

        String signatureCertificate = personalIssueResponse.getData().getSignatureCert();
        String pin = "123456";

        byte[] pfxBinary = this.buildPfx(signatureCertificate, userKeyPair.getPrivate(), pin);
        OutputStream outputStream = new FileOutputStream("/Users/wangjx/Desktop/TEST/s2.pfx");
        IOUtils.write(pfxBinary, outputStream);
        System.out.println("done");
    }

    private byte[] buildPfx(String signatureCertificate, PrivateKey privateKey, String pin) {

        try {
            Certificate entityCertificate = CertificateConverter.fromBase64(signatureCertificate);

//            Certificate[] chain =

        } catch (CertificateException e) {
            e.printStackTrace();
        }

        return null;
    }


}
