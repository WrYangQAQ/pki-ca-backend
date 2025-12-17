package com.algorithm.pki_ca_backend.dto;

public class CertificateApplyRequestDto {
    private String csrPem;
    private String csrSignature;

    public String getCsrPem() { return csrPem; }
    public void setCsrPem(String csrPem) { this.csrPem = csrPem; }

    public String getCsrSignature() { return csrSignature; }
    public void setCsrSignature(String csrSignature) { this.csrSignature = csrSignature; }
}