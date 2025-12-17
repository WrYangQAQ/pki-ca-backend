package com.algorithm.pki_ca_backend.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "Certificates")
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class CertificateEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "CertID")
    private Integer certId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "UserID", nullable = false)   // FK -> Users(UserID)
    @JsonIgnoreProperties({"certificates"})
    private UserEntity user;

    @Column(name = "SerialNumber", nullable = false, unique = true, length = 100)
    private String serialNumber;

    @Column(name = "CertPEM", columnDefinition = "nvarchar(max)", nullable = false)
    private String certPEM;

    @Column(name = "ValidFrom", nullable = false)
    private LocalDateTime validFrom;

    @Column(name = "ValidTo", nullable = false)
    private LocalDateTime validTo;

    @Column(name = "Status", length = 20)
    private String status;   // 有效 / 吊销 / 过期

    @Column(name = "IssueTime")
    private LocalDateTime issueTime;

    @Column(name = "CsrPem", columnDefinition = "nvarchar(max)")
    private String csrPem;
}
