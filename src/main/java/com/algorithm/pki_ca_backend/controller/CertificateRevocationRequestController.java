package com.algorithm.pki_ca_backend.controller;

import com.algorithm.pki_ca_backend.dto.RejectRequestDto;
import com.algorithm.pki_ca_backend.entity.CRLEntity;
import com.algorithm.pki_ca_backend.entity.CertificateEntity;
import com.algorithm.pki_ca_backend.entity.CertificateRevocationRequestEntity;
import com.algorithm.pki_ca_backend.entity.UserEntity;
import com.algorithm.pki_ca_backend.repository.CRLRepository;
import com.algorithm.pki_ca_backend.repository.CertificateRepository;
import com.algorithm.pki_ca_backend.repository.CertificateRevocationRequestRepository;
import com.algorithm.pki_ca_backend.repository.UserRepository;
import com.algorithm.pki_ca_backend.dto.ApiResponse;
import com.algorithm.pki_ca_backend.service.MailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/certificates")
public class CertificateRevocationRequestController {

    private final CertificateRepository certificateRepository;
    private final CertificateRevocationRequestRepository revocationRequestRepository;
    private final UserRepository userRepository;
    private final CRLRepository crlRepository;

    @Autowired
    private final MailService mailService;

    public CertificateRevocationRequestController(
            CertificateRepository certificateRepository,
            CertificateRevocationRequestRepository revocationRequestRepository,
            UserRepository userRepository,
            CRLRepository crlRepository, MailService mailService
    ) {
        this.certificateRepository = certificateRepository;
        this.revocationRequestRepository = revocationRequestRepository;
        this.userRepository = userRepository;
        this.crlRepository = crlRepository;
        this.mailService = mailService;
    }

    // 查询证书吊销请求列表
    @GetMapping("/revoke-requests")
    public ApiResponse<List<CertificateRevocationRequestEntity>> listPendingRequests() {
        return ApiResponse.success(revocationRequestRepository.findByStatus("PENDING"));
    }

    // 通过吊销申请（真正执行吊销）
    @PostMapping("/revoke-requests/{id}/approve")
    public ApiResponse<String> approveRevocationRequest(
            @PathVariable Long id,
            Authentication authentication
    ) {
        Optional<CertificateRevocationRequestEntity> opt =
                revocationRequestRepository.findById(id);

        if (opt.isEmpty()) {
            return ApiResponse.fail("吊销申请不存在");
        }

        CertificateRevocationRequestEntity req = opt.get();

        // 状态校验
        if (!"PENDING".equals(req.getStatus())) {
            return ApiResponse.fail("该吊销申请不是待审批状态");
        }

        // 1. 调用 CRL / 证书吊销逻辑（真正吊销）
        CertificateEntity cert = req.getCertificate();
        cert.setStatus("吊销");          // 如果你已有统一方法，也可以放 Service
        certificateRepository.save(cert);

        // 2. 更新吊销申请状态
        req.setStatus("APPROVED");
        req.setApproveTime(LocalDateTime.now());
        revocationRequestRepository.save(req);

        // 3. 在CRL中插入记录
        CRLEntity crl = new CRLEntity();
        crl.setCertificate(cert);
        crl.setRevokeTime(LocalDateTime.now());
        crl.setReason(req.getReason());
        crlRepository.save(crl);

        // 4. 向用户发送吊销申请通过邮件
        UserEntity user = req.getUser();
        mailService.sendCertificateRevokedMail(
                user.getEmail(),
                user.getUsername(),
                cert.getSerialNumber(),
                req.getReason()
        );

        return ApiResponse.success("证书已成功吊销");
    }


    // 拒绝吊销申请
    @PostMapping("/revoke-requests/{id}/reject")
    public ApiResponse<String> rejectRevocationRequest(
            @PathVariable Long id,
            @RequestBody RejectRequestDto body,
            Authentication authentication
    ) {
        Optional<CertificateRevocationRequestEntity> opt =
                revocationRequestRepository.findById(id);

        if (opt.isEmpty()) {
            return ApiResponse.fail("吊销申请不存在");
        }

        CertificateRevocationRequestEntity req = opt.get();

        if (!"PENDING".equals(req.getStatus())) {
            return ApiResponse.fail("该吊销申请不是待审批状态");
        }

        String operator = authentication.getName();
        String reason = (body == null || body.getReason() == null || body.getReason().trim().isEmpty())
                ? "未提供拒绝原因"
                : body.getReason().trim();

        req.setStatus("REJECTED");
        req.setRejectTime(LocalDateTime.now());
        req.setRejectReason(reason);
        req.setRejectBy(operator);

        revocationRequestRepository.save(req);

        // 向用户发送吊销申请拒绝邮件
        UserEntity user = req.getUser();
        CertificateEntity cert = req.getCertificate();
        mailService.sendCertificateRevocationRejectedMail(
                user.getEmail(),
                user.getUsername(),
                cert.getSerialNumber(),
                req.getRejectReason()
        );

        return ApiResponse.success("已拒绝该吊销申请");
    }


}
