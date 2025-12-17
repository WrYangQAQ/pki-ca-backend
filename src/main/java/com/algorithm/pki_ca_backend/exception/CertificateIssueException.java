package com.algorithm.pki_ca_backend.exception;

public class CertificateIssueException extends Exception {

    public CertificateIssueException(String message) {
        super(message);
    }

    public CertificateIssueException(String message, Throwable cause) {
        super(message, cause);
    }
}

