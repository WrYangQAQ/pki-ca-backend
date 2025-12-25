package com.algorithm.pki_ca_backend.controller;

import com.algorithm.pki_ca_backend.dto.ApiResponse;
import com.algorithm.pki_ca_backend.entity.CertificateEntity;
import com.algorithm.pki_ca_backend.entity.CertificateApplicationRequestEntity;
import com.algorithm.pki_ca_backend.entity.UserEntity;
import com.algorithm.pki_ca_backend.exception.CertificateIssueException;
import com.algorithm.pki_ca_backend.repository.CertificateApplicationRequestRepository;
import com.algorithm.pki_ca_backend.repository.UserRepository;
import com.algorithm.pki_ca_backend.service.CertificateService;
import com.algorithm.pki_ca_backend.service.MailService;
import com.algorithm.pki_ca_backend.service.OperationLogService;
import com.algorithm.pki_ca_backend.dto.RejectRequestDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.Authentication;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;



@RestController
@RequestMapping("/api/certificates")
public class CertificateApplicationRequestController{

    private final UserRepository userRepository;
    private final CertificateApplicationRequestRepository applyRequestRepository;

    @Autowired
    private CertificateService certificateService;

    @Autowired
    private OperationLogService logService;
    @Autowired
    private MailService mailService;

    // 构造器注入
    public CertificateApplicationRequestController(
            UserRepository userRepository,
            CertificateApplicationRequestRepository applyRequestRepository
    ) {
        this.userRepository = userRepository;
        this.applyRequestRepository = applyRequestRepository;
    }

    // 查询待签发证书列表
    @GetMapping("/apply-requests")
    public ApiResponse<List<CertificateApplicationRequestEntity>> listPendingRequests() {
        return ApiResponse.success(applyRequestRepository.findByStatus("PENDING"));
    }


    // 同意请求，完成对请求中CSR的证书签发
    @PostMapping("/apply-requests/{id}/approve")
    public ApiResponse<Long> approveRequest(@PathVariable Long id, Authentication authentication){
        // 1. 查找证书申请
        Optional<CertificateApplicationRequestEntity> opt =
                applyRequestRepository.findById(id);

        if (opt.isEmpty()) {
            return ApiResponse.fail("证书申请不存在");
        }

        CertificateApplicationRequestEntity req = opt.get();

        // 2. 校验状态
        if (!"PENDING".equals(req.getStatus())) {
            return ApiResponse.fail("该申请不是待审批状态");
        }

        // 3. 调用 CA 服务签发证书
        CertificateEntity cert;
        try {
            cert = certificateService.issueCertificateFromRequest(
                    req,
                    authentication.getName()   // ADMIN 用户名
            );
        } catch (CertificateIssueException e) {
            return ApiResponse.fail(e.getMessage());
        }

        // 4. 更新申请状态
        req.setStatus("APPROVED");
        req.setApproveTime(LocalDateTime.now());
        applyRequestRepository.save(req);

        // 5. 返回证书 ID
        return ApiResponse.success(cert.getCertId().longValue());
    }


    // 拒绝签发接口
    @PostMapping("/apply-requests/{id}/reject")
    public ApiResponse<String> rejectRequest(
            @PathVariable Long id,
            @RequestBody RejectRequestDto body,
            Authentication authentication
    ) {
        Optional<CertificateApplicationRequestEntity> opt =
                applyRequestRepository.findById(id);
        if (opt.isEmpty()) {
            return ApiResponse.fail("证书申请不存在");
        }
        CertificateApplicationRequestEntity req = opt.get();


        if (!"PENDING".equals(req.getStatus())) {
            return ApiResponse.fail("该申请不是待审批状态");
        }


        String operator = authentication.getName();
        String reason = (body == null || body.getReason() == null || body.getReason().trim().isEmpty())
                ? "未提供拒绝原因"
                : body.getReason().trim();

        req.setStatus("REJECTED");
        req.setRejectTime(LocalDateTime.now());
        req.setRejectReason(reason);
        req.setRejectBy(operator);

        applyRequestRepository.save(req);

        logService.record(
                operator,
                "拒绝签发证书",
                "CertificateRequest",
                "requestId=" + req.getRequestId() + ", reason=" + reason
        );

        // 向用户发送申请拒绝邮件
        UserEntity user = req.getUser();
        mailService.sendCertificateIssueRejectedMail(
                user.getEmail(),
                user.getUsername(),
                req.getRejectReason()
        );

        return ApiResponse.success("已拒绝该证书申请");
    }


}
