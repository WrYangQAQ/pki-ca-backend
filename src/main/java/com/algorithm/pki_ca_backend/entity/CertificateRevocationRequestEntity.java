package com.algorithm.pki_ca_backend.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "CertificateRevocationRequests")
public class CertificateRevocationRequestEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long requestId;

    /* 被吊销的证书 */
    @ManyToOne(optional = false)
    @JoinColumn(name = "CertID")
    private CertificateEntity certificate;

    /* 申请人 */
    @ManyToOne(optional = false)
    @JoinColumn(name = "UserID")
    private UserEntity user;

    /* 吊销原因 */
    @Column(nullable = false, length = 500)
    private String reason;

    /* 申请状态：PENDING / APPROVED / REJECTED */
    @Column(nullable = false)
    private String status;

    /* 申请时间 */
    @Column(nullable = false)
    private LocalDateTime requestTime;

    /* 审批时间 */
    private LocalDateTime approveTime;

    /* ===== 拒绝相关字段 ===== */

    @Column(name = "RejectTime")
    private LocalDateTime rejectTime;

    @Column(name = "RejectReason", length = 500)
    private String rejectReason;

    @Column(name = "RejectBy", length = 100)
    private String rejectBy;
}
