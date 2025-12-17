package com.algorithm.pki_ca_backend.controller;

import com.algorithm.pki_ca_backend.dto.ApiResponse;
import com.algorithm.pki_ca_backend.entity.CertificateEntity;
import com.algorithm.pki_ca_backend.entity.CertificateApplicationRequestEntity;
import com.algorithm.pki_ca_backend.entity.CertificateRevocationRequestEntity;
import com.algorithm.pki_ca_backend.entity.UserEntity;
import com.algorithm.pki_ca_backend.repository.CertificateApplicationRequestRepository;
import com.algorithm.pki_ca_backend.repository.CertificateRepository;
import com.algorithm.pki_ca_backend.repository.CertificateRevocationRequestRepository;
import com.algorithm.pki_ca_backend.repository.UserRepository;
import com.algorithm.pki_ca_backend.service.CertificateService;
import com.algorithm.pki_ca_backend.service.OperationLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.Authentication;


import java.time.LocalDateTime;
import java.util.*;

@RestController
@RequestMapping("/api/certificates")
public class CertificateController{

    private final UserRepository userRepository;
    private final CertificateApplicationRequestRepository applyRequestRepository;
    private final CertificateRevocationRequestRepository revokeRequestRepository;
    private final CertificateRepository certificateRepository;


    // 构造器注入
    public CertificateController(
            UserRepository userRepository,
            CertificateApplicationRequestRepository applyRequestRepository,
            CertificateRevocationRequestRepository revokeRequestRepository,
            CertificateRepository certificateRepository,
            OperationLogService logService,
            CertificateService certificateService
    ) {
        this.userRepository = userRepository;
        this.applyRequestRepository = applyRequestRepository;
        this.revokeRequestRepository = revokeRequestRepository;
        this.certificateRepository = certificateRepository;
        this.logService = logService;
        this.certificateService = certificateService;
    }


    @Autowired
    private OperationLogService logService;

    @Autowired
    private CertificateService certificateService;

    // 查询所有证书
    @GetMapping
    public ApiResponse<List<CertificateEntity>> getAllCertificates(){
        List<CertificateEntity> list = certificateService.getAllCertificates();
        return ApiResponse.success(list);
    }

    // 查询自己的证书
    @GetMapping("/my")
    public ApiResponse<List<Map<String, Object>>> getMyCertificates(
            Authentication authentication
    ) {
        String username = authentication.getName();

        Optional<UserEntity> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            return ApiResponse.fail("用户不存在");
        }
        UserEntity user = userOpt.get();

        List<CertificateEntity> certs =
                certificateRepository.findByUser(user);

        List<Map<String, Object>> result = new ArrayList<>();

        for (CertificateEntity cert : certs) {
            Map<String, Object> item = new HashMap<>();
            item.put("serialNumber", cert.getSerialNumber());
            item.put("status", certificateService.evaluateCertificateStatus(cert));
            item.put("validFrom", cert.getValidFrom());
            item.put("validTo", cert.getValidTo());
            result.add(item);
        }

        return ApiResponse.success(result);
    }

    // 签发新证书（！！！ 签发旧接口，不再使用，但为了系统稳定不进行删除）
    @PostMapping("/issue")
    public ApiResponse<CertificateEntity> issueCertificate(
            @RequestParam Integer userId,
            @RequestBody CertificateEntity cert){

        CertificateEntity saved = certificateService.issueCertificate(userId, cert);

        if (saved == null){
            return ApiResponse.fail("用户不存在或证书序列号已存在");
        }

        return ApiResponse.success(saved);
    }

    // 查询证书状态
    @GetMapping("/{certId}/status")
    public ApiResponse<String> getCertificateStatus(@PathVariable Integer certId){

        CertificateEntity cert = certificateService.getCertificateById(certId);

        if (cert == null){
            return ApiResponse.fail("证书不存在");
        }

        String status = certificateService.evaluateCertificateStatus(cert);
        return ApiResponse.success(status);
    }

    // 根据SerialNumber查询证书(只查询证书状态)
    @GetMapping("/status")
    public ApiResponse<String> getCertificateStatusBySerialNumber(@RequestParam String serialNumber){

        CertificateEntity cert =
                certificateService.getCertificateBySerialNumber(serialNumber);

        if (cert == null){
            return ApiResponse.fail("证书不存在");
        }

        String status = certificateService.evaluateCertificateStatus(cert);
        return ApiResponse.success(status);
    }

    // 根据SerialNumber的证书验证接口(更加详细的查询接口，返回证书状态以及具体起用，过期时间)
    @GetMapping("/{serialNumber}/verify")
    public ApiResponse<Map<String, Object>> verifyCertificate(
            @PathVariable String serialNumber){

        // 1. 根据序列号查证书
        CertificateEntity cert = certificateService.getCertificateBySerialNumber(serialNumber);

        if(cert == null){
            return ApiResponse.fail("证书不存在");
        }

        // 2. 计算证书状态
        String status = certificateService.evaluateCertificateStatus(cert);

        // 3. 状态不是“有效”则视为不可信
        if (!"有效".equals(status)){
            return ApiResponse.fail("证书不可用，状态：" + status);
        }

        // 4. 构造验证成功返回数据
        Map<String, Object> data = new HashMap<>();
        data.put("status", status);
        data.put("validFrom", cert.getValidFrom());
        data.put("validTo", cert.getValidTo());

        return ApiResponse.success(data);
    }

    // 发出证书申请请求
    @PostMapping("/apply-request")
    public ApiResponse<Long> applyCertificate(Authentication authentication) {

        String username = authentication.getName();
        Optional<UserEntity> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            return ApiResponse.fail("用户不存在");
        }
        UserEntity user = userOpt.get();

        CertificateApplicationRequestEntity req = new CertificateApplicationRequestEntity();
        req.setUser(user);
        req.setPublicKey(user.getPublicKey());
        req.setStatus("PENDING");
        req.setRequestTime(LocalDateTime.now());

        // 持久化保存
        CertificateApplicationRequestEntity saved = applyRequestRepository.save(req);

        // 记录日志
        logService.record(
                username,
                "申请证书",
                "CertificateRequest",
                "requestId=" + saved.getRequestId()
        );

        return ApiResponse.success(saved.getRequestId());
    }

    // 发出证书吊销申请请求
    @PostMapping("/{serialNumber}/revoke-request")
    public ApiResponse<Long> revokeCertificate(
            @PathVariable String serialNumber,
            @RequestBody Map<String, String> body,
            Authentication authentication
    ) {

        String username = authentication.getName();
        Optional<UserEntity> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            return ApiResponse.fail("用户不存在");
        }
        UserEntity user = userOpt.get();

        // 查询证书
        Optional<CertificateEntity> certOpt = certificateRepository.findBySerialNumber(serialNumber);
        if (certOpt.isEmpty()) {
            return ApiResponse.fail("证书不存在");
        }
        CertificateEntity cert = certOpt.get();

        // 校验证书归属
        if (!cert.getUser().getUserId().equals(user.getUserId())) {
            return ApiResponse.fail("无权吊销该证书");
        }

        // 校验证书状态
        if (!"有效".equals(cert.getStatus())) {
            return ApiResponse.fail("当前证书状态不可申请吊销");
        }

        // 吊销原因
        String reason = body.get("reason");
        if (reason == null || reason.trim().isEmpty()) {
            return ApiResponse.fail("请填写吊销原因");
        }

        // 构造吊销申请
        CertificateRevocationRequestEntity req =
                new CertificateRevocationRequestEntity();
        req.setCertificate(cert);
        req.setUser(user);
        req.setReason(reason.trim());
        req.setStatus("PENDING");
        req.setRequestTime(LocalDateTime.now());

        // 持久化保存
        CertificateRevocationRequestEntity saved =
                revokeRequestRepository.save(req);

        // 记录日志
        logService.record(
                username,
                "申请吊销证书",
                "CertificateRevocationRequest",
                "requestId=" + saved.getRequestId()
        );

        return ApiResponse.success(saved.getRequestId());
    }


    // 根据证书id下载证书
    @GetMapping("/{certId}/download")
    public ResponseEntity<String> downloadCertificate(
            @PathVariable Integer certId,
            Authentication authentication
    ) {

        CertificateEntity cert =
                certificateService.getCertificateById(certId);

        if (cert == null) {
            return ResponseEntity.notFound().build();
        }

        String username = authentication.getName();
        String role = authentication.getAuthorities()
                .iterator().next().getAuthority();

        // USER 只能下载自己的证书
        if ("ROLE_USER".equals(role)) {
            if (!cert.getUser().getUsername().equals(username)) {
                throw new org.springframework.security.access.AccessDeniedException("无权下载该证书");
            }
        }

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=certificate-" + certId + ".pem")
                .contentType(MediaType.valueOf("application/x-pem-file"))
                .body(cert.getCertPEM());
    }


}
