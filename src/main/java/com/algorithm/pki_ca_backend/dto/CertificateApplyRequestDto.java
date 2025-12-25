package com.algorithm.pki_ca_backend.dto;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CertificateApplyRequestDto {
    private String csrPem;
    private String csrSignature;
}