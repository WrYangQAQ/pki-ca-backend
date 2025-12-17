package com.algorithm.pki_ca_backend.dto;

import org.bouncycastle.asn1.x500.X500Name;
import java.security.PublicKey;

public class CsrInfo {
    private final X500Name subject;
    private final PublicKey csrPublicKey;

    public CsrInfo(X500Name subject, PublicKey publicKey) {
        this.subject = subject;
        this.csrPublicKey = publicKey;
    }
    public X500Name getSubject() { return subject; }
    public PublicKey getCsrPublicKey() { return csrPublicKey; }
}
