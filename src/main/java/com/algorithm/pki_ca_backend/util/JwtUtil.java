package com.algorithm.pki_ca_backend.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Date;

public class JwtUtil {

    // 使用 jjwt 官方推荐方式生成安全的 HS256 密钥
    // 长度 >= 256 bits，符合 RFC 7518
    private static final SecretKey KEY =
            Keys.secretKeyFor(SignatureAlgorithm.HS256);

    // Token 有效期设为 1h
    private static final long EXPIRE_MS = 60 * 60 * 1000;

    // 生成 JWT
    public static String generateToken(String username, String role) {
        return Jwts.builder()
                .setSubject(username)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRE_MS))
                .signWith(KEY)
                .compact();
    }


    // 解析 JWT
    public static Claims parseToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(KEY)   // 关键修改点
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
