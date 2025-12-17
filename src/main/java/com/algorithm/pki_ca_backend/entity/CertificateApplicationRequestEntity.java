package com.algorithm.pki_ca_backend.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "CertificateRequests")
public class CertificateApplicationRequestEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long requestId;

    @ManyToOne(optional = false)
    @JoinColumn(name = "UserID")
    private UserEntity user;

    @Column(name = "LoginPublicKey", nullable = false, columnDefinition = "TEXT")
    private String loginPublicKey;

    @Column(nullable = false)
    private String status;   // PENDING / ISSUED / REJECTED

    @Column(nullable = false)
    private LocalDateTime requestTime;

    private LocalDateTime approveTime;

    @Column(name = "CsrPem", columnDefinition = "nvarchar(max)")
    private String csrPem;

    // ===== 拒绝相关字段 =====

    @Column(name = "RejectTime")
    private LocalDateTime rejectTime;

    @Column(name = "RejectReason", length = 500)
    private String rejectReason;

    @Column(name = "RejectBy", length = 100)
    private String rejectBy;
}

