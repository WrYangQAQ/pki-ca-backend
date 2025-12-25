package com.algorithm.pki_ca_backend.service;

import com.algorithm.pki_ca_backend.dto.CsrBindChallenge;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class CsrChallengeService {
    private final ConcurrentHashMap<String, CsrBindChallenge> cache = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    public CsrBindChallenge generate(String username) {
        byte[] buf = new byte[32];
        random.nextBytes(buf);
        String challenge = Base64.getEncoder().encodeToString(buf);
        CsrBindChallenge csrBindChallenge = new CsrBindChallenge(challenge, LocalDateTime.now().plusMinutes(5));
        cache.put(username, csrBindChallenge);
        //System.out.println("csrBindChallenge: " + challenge);
        return csrBindChallenge;
    }

    public CsrBindChallenge get(String username) { return cache.get(username); }
    public void consume(String username) { cache.remove(username); }
}

