package com.algorithm.pki_ca_backend.util;

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
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

public class CertificateUtil {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }


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

    // ===== 工具方法 =====

    // 加载CA私钥
    private static PrivateKey loadCaPrivateKey() throws CertificateIssueException {

        InputStream is = CertificateUtil.class
                .getClassLoader()
                .getResourceAsStream("ca/ca.key.pem");

        if (is == null) {
            throw new CertificateIssueException("CA 私钥文件 ca.key.pem 未找到");
        }

        try (PEMParser parser = new PEMParser(new InputStreamReader(is))) {

            Object obj = parser.readObject();
            JcaPEMKeyConverter converter =
                    new JcaPEMKeyConverter().setProvider("BC");

            // PKCS#1：BEGIN RSA PRIVATE KEY
            if (obj instanceof PEMKeyPair keyPair) {
                return converter.getKeyPair(keyPair).getPrivate();
            }

            // PKCS#8：BEGIN PRIVATE KEY
            if (obj instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo keyInfo) {
                return converter.getPrivateKey(keyInfo);
            }

            throw new CertificateIssueException("不支持的 CA 私钥格式：" + obj.getClass().getName());
        } catch (CertificateIssueException e){
            // 业务异常，直接向上抛
            throw e;
        } catch (Exception e) {
            // IO / PEM 解析异常，统一包装
            throw new CertificateIssueException("加载 CA 私钥失败：" + e.getMessage(), e);
        }
    }


    private static X509Certificate loadCaCertificate() throws Exception {
        InputStream is = CertificateUtil.class
                .getClassLoader()
                .getResourceAsStream("ca/ca.cert.pem");

        try (PEMParser parser = new PEMParser(new InputStreamReader(is))) {
            X509CertificateHolder holder =
                    (X509CertificateHolder) parser.readObject();

            return new JcaX509CertificateConverter()
                    .setProvider("BC")
                    .getCertificate(holder);
        }
    }

    private static PublicKey parsePublicKey(String pem) throws Exception {
        String content = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(content);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);

        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }
}
