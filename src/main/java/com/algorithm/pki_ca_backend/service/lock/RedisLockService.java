package com.algorithm.pki_ca_backend.service.lock;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.UUID;

@Service
public class RedisLockService {

    private final StringRedisTemplate redisTemplate;

    // 锁过期时间（秒）
    private static final Duration LOCK_TTL = Duration.ofSeconds(5);

    public RedisLockService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }


    // 尝试对目标线程加锁，返回true则获取成功，返回false则表明锁已被占用
    public boolean tryLock(String lockKey) {

        // value 用 UUID，便于调试与安全释放
        String lockValue = UUID.randomUUID().toString();

        Boolean success = redisTemplate.opsForValue()
                .setIfAbsent(lockKey, lockValue, LOCK_TTL);

        return Boolean.TRUE.equals(success);
    }

    // 释放线程锁
    public void unlock(String lockKey) {
        redisTemplate.delete(lockKey);
    }

}
