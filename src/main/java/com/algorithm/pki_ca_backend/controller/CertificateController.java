package com.algorithm.pki_ca_backend.controller;

import com.algorithm.pki_ca_backend.dto.ApiResponse;
import com.algorithm.pki_ca_backend.dto.CertificateApplyRequestDto;
import com.algorithm.pki_ca_backend.dto.CsrBindChallenge;
import com.algorithm.pki_ca_backend.dto.CsrInfo;
import com.algorithm.pki_ca_backend.entity.CertificateEntity;
import com.algorithm.pki_ca_backend.entity.CertificateApplicationRequestEntity;
import com.algorithm.pki_ca_backend.entity.CertificateRevocationRequestEntity;
import com.algorithm.pki_ca_backend.entity.UserEntity;
import com.algorithm.pki_ca_backend.exception.CertificateIssueException;
import com.algorithm.pki_ca_backend.repository.CertificateApplicationRequestRepository;
import com.algorithm.pki_ca_backend.repository.CertificateRepository;
import com.algorithm.pki_ca_backend.repository.CertificateRevocationRequestRepository;
import com.algorithm.pki_ca_backend.repository.UserRepository;
import com.algorithm.pki_ca_backend.service.CertificateService;
import com.algorithm.pki_ca_backend.service.CsrChallengeService;
import com.algorithm.pki_ca_backend.service.OperationLogService;
import com.algorithm.pki_ca_backend.util.CertificateUtil;
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

    @Autowired
    private CsrChallengeService csrChallengeService;

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
        data.put("username", cert.getUser().getUsername());

        return ApiResponse.success(data);
    }

    // 发出证书申请请求
    @PostMapping("/apply-request")
    public ApiResponse<Long> applyCertificate(
            Authentication authentication,
            @RequestBody CertificateApplyRequestDto body
    ) {
        // 返回请求体为空的API响应
        if (body == null) {
            return ApiResponse.fail("请求体不能为空");
        }

        // 返回CSR为空的API响应
        if (body == null || body.getCsrPem() == null || body.getCsrPem().trim().isEmpty()) {
            return ApiResponse.fail("csrPem 不能为空");
        }

        // 返回challenge签名为空的API响应
        if (body.getCsrSignature() == null || body.getCsrSignature().trim().isEmpty()) {
            return ApiResponse.fail("csrSignature 不能为空");
        }


        String username = authentication.getName();
        Optional<UserEntity> userOpt = userRepository.findByUsername(username);


        if (userOpt.isEmpty()) {
            return ApiResponse.fail("用户不存在");
        }

        CsrBindChallenge csrBindChallenge = csrChallengeService.get(username);
        if (csrBindChallenge == null) {
            return ApiResponse.fail("CSR challenge 不存在，请重新获取");
        }
        if (csrBindChallenge == null || csrBindChallenge.isExpired()) {
            return ApiResponse.fail("CSR challenge 无效或已过期");
        }

        //System.out.println("csrSignature:" + body.getCsrSignature().toString());

        try {
            CsrInfo csrInfo = CertificateUtil.parseCsrAndExtractPublicKey(body.getCsrPem());
            CertificateUtil.verifyCsrBinding(csrInfo.getCsrPublicKey(),
                                             csrBindChallenge.getChallenge(),
                                             body.getCsrSignature()
            );

            csrChallengeService.consume(username); // 一次性

            CertificateApplicationRequestEntity req = new CertificateApplicationRequestEntity();
            req.setUser(userOpt.get());
            req.setCsrPem(body.getCsrPem().trim());
            req.setStatus("PENDING");
            req.setRequestTime(LocalDateTime.now());

            CertificateApplicationRequestEntity saved = applyRequestRepository.save(req);

            logService.record(
                    username,
                    "申请证书（CSR + Challenge 绑定）",
                    "CertificateRequest",
                    "requestId=" + saved.getRequestId()
            );
            return ApiResponse.success(saved.getRequestId());

        } catch (CertificateIssueException e) {
            return ApiResponse.fail(e.getMessage());
        }
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


    // 根据证书序列号下载证书
    @GetMapping("/{serialNumber}/download")
    public ResponseEntity<String> downloadCertificate(
            @PathVariable String serialNumber,
            Authentication authentication
    ) {

        CertificateEntity cert =
                certificateService.getCertificateBySerialNumber(serialNumber);

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
                        "attachment; filename=certificate-" + serialNumber + ".pem")
                .contentType(MediaType.valueOf("application/x-pem-file"))
                .body(cert.getCertPEM());
    }

    // 请求一个CSR challenge
    @PostMapping("/csr/challenge")
    public ApiResponse<String> getCsrChallenge(Authentication authentication) {
        String username = authentication.getName();
        return ApiResponse.success(csrChallengeService.generate(username).getChallenge());
    }


}
