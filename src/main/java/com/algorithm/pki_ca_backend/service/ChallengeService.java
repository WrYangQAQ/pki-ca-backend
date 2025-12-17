package com.algorithm.pki_ca_backend.service;

import com.algorithm.pki_ca_backend.dto.LoginChallenge;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class ChallengeService {

    // 存储用户名到登录挑战的映射（线程安全）
    private final Map<String, LoginChallenge> challengeStore = new ConcurrentHashMap<>();

    // 为指定用户名生成新的登录挑战
    public LoginChallenge generate(String username) {
        // 生成随机挑战字符串（移除UUID中的连字符）
        String challenge = UUID.randomUUID().toString().replace("-", "");
        // 设置挑战有效期为5分钟
        LocalDateTime expireAt = LocalDateTime.now().plusMinutes(5);

        // 创建挑战对象并存储
        LoginChallenge lc = new LoginChallenge(challenge, expireAt);
        challengeStore.put(username, lc);

        return lc;
    }

    // 获取指定用户名的登录挑战
    public LoginChallenge get(String username) {
        return challengeStore.get(username);
    }

    // 移除指定用户名的登录挑战
    public void remove(String username) {
        challengeStore.remove(username);
    }

    // 校验 challenge 是否匹配且未过期
    public boolean validate(String username, String challenge) {
        LoginChallenge lc = challengeStore.get(username);
        if (lc == null || lc.isExpired()) {
            return false;
        }
        return lc.getChallenge().equals(challenge);
    }

    // 关键：一次性消费 challenge
    public void consume(String username) {
        challengeStore.remove(username);
    }
}