package com.algorithm.pki_ca_backend.util;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class RsaSignatureUtil {

    // 支持两种存储：PEM（含 BEGIN/END）或纯 Base64（无头尾）
    public static PublicKey parseRsaPublicKey(String pemOrBase64) throws Exception {
        if (pemOrBase64 == null) {
            throw new IllegalArgumentException("publicKey is null");
        }

        String s = pemOrBase64
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", ""); // 去掉所有空白（换行/空格）

        byte[] keyBytes = Base64.getDecoder().decode(s);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);

        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    // 调用RSA验签方法
    public static boolean verifySha256WithRsa(PublicKey publicKey, String message, String signatureBase64)
            throws Exception {

        byte[] sigBytes = Base64.getDecoder().decode(signatureBase64);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        return signature.verify(sigBytes);
    }


    // 调用 SHA256 对输入字符串进行哈希值计算
    public static String sha256Hex(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

}
