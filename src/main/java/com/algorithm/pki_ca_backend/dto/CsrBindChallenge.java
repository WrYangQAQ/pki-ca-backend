package com.algorithm.pki_ca_backend.dto;

import java.time.LocalDateTime;

public class CsrBindChallenge {
    private final String challenge;
    private final LocalDateTime expireAt;

    public CsrBindChallenge(String challenge, LocalDateTime expireAt) {
        this.challenge = challenge;
        this.expireAt = expireAt;
    }
    public String getChallenge() { return challenge; }
    public boolean isExpired() { return LocalDateTime.now().isAfter(expireAt); }
}

