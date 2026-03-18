package com.algorithm.pki_ca_backend.util;

import com.algorithm.pki_ca_backend.dto.CsrInfo;
import com.algorithm.pki_ca_backend.exception.CertificateIssueException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public class CertificateUtil {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }


    // 旧签发方法，只适用于直接给用户进行签发(停止使用)
    public static String issueX509(String userPublicKeyPem, String serialNumber) throws CertificateIssueException {

        try {
            // 1. 读取 CA 私钥
            PrivateKey caPrivateKey = loadCaPrivateKey();

            // 2. 读取 CA 证书（用于 Issuer）
            X509Certificate caCert = loadCaCertificate();

            // 3. 解析用户公钥
            PublicKey userPublicKey = parsePublicKey(userPublicKeyPem);

            // 4. 构造证书基本信息
            X500Name issuer = new X500Name(caCert.getSubjectX500Principal().getName());
            X500Name subject = new X500Name("CN=PKI User");

            Instant now = Instant.now();
            Date notBefore = Date.from(now);
            Date notAfter = Date.from(now.plus(365, ChronoUnit.DAYS));

            BigInteger serial = new BigInteger(serialNumber.replaceAll("\\D", ""));

            X509v3CertificateBuilder builder =
                    new JcaX509v3CertificateBuilder(
                            issuer,
                            serial,
                            notBefore,
                            notAfter,
                            subject,
                            userPublicKey
                    );

            // 5. 添加 X.509 v3 扩展
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

            builder.addExtension(
                    Extension.basicConstraints,
                    true,
                    new BasicConstraints(false)
            );

            builder.addExtension(
                    Extension.keyUsage,
                    true,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment)
            );

            builder.addExtension(
                    Extension.subjectKeyIdentifier,
                    false,
                    extUtils.createSubjectKeyIdentifier(userPublicKey)
            );

            // 6. 使用 CA 私钥签名
            ContentSigner signer =
                    new JcaContentSignerBuilder("SHA256withRSA")
                            .setProvider("BC")
                            .build(caPrivateKey);

            X509CertificateHolder holder = builder.build(signer);

            X509Certificate cert =
                    new JcaX509CertificateConverter()
                            .setProvider("BC")
                            .getCertificate(holder);

            // 7. 输出 PEM
            StringWriter sw = new StringWriter();
            try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
                pw.writeObject(cert);
            }

            return sw.toString();

        } catch (Exception e) {
            throw new CertificateIssueException("X509 证书签发失败：" + e.getMessage(), e);
        }
    }


    // 新方法，通过CSR来给用户签发标准X.509证书
    public static String issueX509FromCsr(
            PublicKey csrPublicKey,
            X500Name subject,
            String serialNumber
    ) throws CertificateIssueException {

        System.out.println("[DEBUG] issueX509FromCsr() ENTER");

        try {
            PrivateKey caPrivateKey = loadCaPrivateKey();

            X509Certificate caCert = loadCaCertificate();

            X500Name issuer = new X500Name(caCert.getSubjectX500Principal().getName());

            Instant now = Instant.now();
            Date notBefore = Date.from(now);
            Date notAfter = Date.from(now.plus(365, ChronoUnit.DAYS));

            BigInteger serial = new BigInteger(serialNumber.replaceAll("\\D", ""));

            JcaX509v3CertificateBuilder builder =
                    new JcaX509v3CertificateBuilder(
                            issuer,
                            serial,
                            notBefore,
                            notAfter,
                            subject,
                            csrPublicKey
                    );

            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

            builder.addExtension(
                    Extension.basicConstraints,
                    true,
                    new BasicConstraints(false)
            );

            builder.addExtension(
                    Extension.keyUsage,
                    true,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment)
            );

            builder.addExtension(
                    Extension.subjectKeyIdentifier,
                    false,
                    extUtils.createSubjectKeyIdentifier(csrPublicKey)
            );

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider("BC")
                    .build(caPrivateKey);

            X509CertificateHolder holder = builder.build(signer);

            X509Certificate cert =
                    new JcaX509CertificateConverter()
                            .setProvider("BC")
                            .getCertificate(holder);

            StringWriter sw = new StringWriter();
            try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
                pw.writeObject(cert);
            }


            return sw.toString();

        } catch (Exception e) {
            throw new CertificateIssueException("X509 证书签发失败：" + e.getMessage(), e);
        }
    }


    // ===== 工具方法 =====

    // 从 KeyStore 加载 CA 私钥
    private static PrivateKey loadCaPrivateKey() throws CertificateIssueException {
        try {
            String keystorePassword = System.getenv("CA_KEYSTORE_PASSWORD");
            String keyAlias = System.getenv("CA_KEY_ALIAS");

            if (keyAlias == null || keystorePassword == null) {
                throw new CertificateIssueException("CA KeyStore 环境变量未配置");
            }

            KeyStore keyStore = loadCaKeyStore();

            Key key = keyStore.getKey(keyAlias, keystorePassword.toCharArray());
            if (!(key instanceof PrivateKey)) {
                throw new CertificateIssueException("KeyStore 中未找到 CA 私钥");
            }

            return (PrivateKey) key;

        } catch (CertificateIssueException e) {
            throw e;
        } catch (Exception e) {
            throw new CertificateIssueException("加载 CA 私钥失败：" + e.getMessage(), e);
        }
    }


    // 从 KeyStore 加载根证书
    private static X509Certificate loadCaCertificate() throws CertificateIssueException {
        try {
            String keyAlias = System.getenv("CA_KEY_ALIAS");
            if (keyAlias == null) {
                throw new CertificateIssueException("CA KeyStore 别名未配置");
            }

            KeyStore keyStore = loadCaKeyStore();
            Certificate cert = keyStore.getCertificate(keyAlias);

            if (!(cert instanceof X509Certificate)) {
                throw new CertificateIssueException("KeyStore 中未找到 CA 证书");
            }

            return (X509Certificate) cert;

        } catch (CertificateIssueException e) {
            throw e;
        } catch (Exception e) {
            throw new CertificateIssueException("加载 CA 证书失败：" + e.getMessage(), e);
        }
    }


    // 解析PEM格式公钥
    private static PublicKey parsePublicKey(String pem) throws Exception {
        String content = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = java.util.Base64.getDecoder().decode(content);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);

        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    // 解析收到的CSR PEM
    public static CsrInfo parseCsrAndExtractPublicKey(String csrPem) throws CertificateIssueException {
        try (PEMParser parser = new PEMParser(new StringReader(csrPem))) {

            Object obj = parser.readObject();
            if (!(obj instanceof PKCS10CertificationRequest csr)) {
                throw new CertificateIssueException("CSR 格式错误：不是 PKCS#10");
            }

            JcaPKCS10CertificationRequest jcaCsr = new JcaPKCS10CertificationRequest(csr).setProvider("BC");
            PublicKey csrPublicKey = jcaCsr.getPublicKey();
            X500Name subject = csr.getSubject();

            //System.out.println("publicKey:" + publicKeyToPEM(csrPublicKey));

            return new CsrInfo(subject, csrPublicKey);

        }  catch (Exception e) {
            throw new CertificateIssueException("解析/验证 CSR 失败：" + e.getMessage(), e);
        }
    }

    // 用CSR公钥验签
    public static void verifyCsrBinding(
            PublicKey csrPublicKey,
            String challenge,
            String signatureBase64
    ) throws CertificateIssueException {

        try {
            byte[] sigBytes = java.util.Base64.getDecoder().decode(signatureBase64);

            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(csrPublicKey);
            sig.update(challenge.getBytes(StandardCharsets.UTF_8));

            if (!sig.verify(sigBytes)) {
                throw new CertificateIssueException("CSR 私钥绑定验证失败");
            }

        } catch (CertificateIssueException e) {
            throw e;
        } catch (Exception e) {
            throw new CertificateIssueException("CSR 私钥绑定校验异常：" + e.getMessage(), e);
        }
    }


    // 将公钥转换为 Base64 编码字符串
    // @param publicKey 公钥对象
    // @return Base64 编码的字符串
    public static String publicKeyToBase64(PublicKey publicKey) {
        byte[] encoded = publicKey.getEncoded();  // X.509 格式编码
        return java.util.Base64.getEncoder().encodeToString(encoded);
    }


    // 加载 KeyStore
    private static KeyStore loadCaKeyStore() throws CertificateIssueException {
        try {
            String keystorePath = System.getenv("CA_KEYSTORE_PATH");
            String keystorePassword = System.getenv("CA_KEYSTORE_PASSWORD");

            if (keystorePath == null || keystorePassword == null) {
                throw new CertificateIssueException("CA KeyStore 环境变量未配置");
            }

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream is = new FileInputStream(keystorePath)) {
                keyStore.load(is, keystorePassword.toCharArray());
            }

            return keyStore;

        } catch (Exception e) {
            throw new CertificateIssueException("加载 CA KeyStore 失败：" + e.getMessage(), e);
        }
    }
}
