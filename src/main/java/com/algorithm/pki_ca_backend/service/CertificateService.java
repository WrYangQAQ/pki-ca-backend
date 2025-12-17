package com.algorithm.pki_ca_backend.service;

import com.algorithm.pki_ca_backend.entity.CertificateEntity;
import com.algorithm.pki_ca_backend.entity.CertificateApplicationRequestEntity;
import com.algorithm.pki_ca_backend.entity.UserEntity;
import com.algorithm.pki_ca_backend.exception.CertificateIssueException;
import com.algorithm.pki_ca_backend.repository.CRLRepository;
import com.algorithm.pki_ca_backend.repository.CertificateRepository;
import com.algorithm.pki_ca_backend.repository.UserRepository;
import com.algorithm.pki_ca_backend.util.CertificateUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class CertificateService {

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    public OperationLogService logService;

    @Autowired
    private CRLRepository CRLRepository;

    // 查询所有证书
    public List<CertificateEntity> getAllCertificates() {
        return certificateRepository.findAll();
    }

    // 签发证书 !!!（旧的直接签发接口，仅为维持系统稳定这里不做删除，但不再使用）
    public CertificateEntity issueCertificate(Integer userId, CertificateEntity cert) {

        // 检查用户是否存在
        UserEntity user = userRepository.findById(userId).orElse(null);
        if (user == null) {
            return null;
        }

        // 检查序列号是否唯一
        if (certificateRepository.existsBySerialNumber(cert.getSerialNumber())) {
            return null;
        }

        // 设置关联与自动字段
        cert.setUser(user);
        cert.setStatus("有效");
        cert.setIssueTime(LocalDateTime.now());
        CertificateEntity savedCert = certificateRepository.save(cert);

        // 写入操作日志
        logService.record(
                "System",                        // 暂时写死
                "签发证书",
                savedCert.getSerialNumber(),
                "颁发给用户：" + user.getUsername()
        );

        return savedCert;
    }

    // 基于证书申请的 CA 签发流程（新方法，ADMIN 专用）
    public CertificateEntity issueCertificateFromRequest(
            CertificateApplicationRequestEntity request,
            String operatorUsername   // ADMIN 用户名，用于日志
    ) throws CertificateIssueException {

        UserEntity user = request.getUser();

        // 1. 生成唯一序列号
        String serialNumber = "SN-" + System.currentTimeMillis();

        // 2. 使用 CA 私钥签发证书
        String certPem;
        try {
            certPem = CertificateUtil.issueX509(
                    request.getPublicKey(),
                    serialNumber
            );
        } catch (CertificateIssueException e) {
            // 在 Service 层补充业务上下文信息
            throw new CertificateIssueException(
                    "为用户 [" + user.getUsername() + "] 签发证书失败",
                    e
            );
        }

        // 3. 构造证书实体
        CertificateEntity cert = new CertificateEntity();
        cert.setUser(user);
        cert.setSerialNumber(serialNumber);
        cert.setCertPEM(certPem);
        cert.setValidFrom(LocalDateTime.now());
        cert.setValidTo(LocalDateTime.now().plusYears(1));
        cert.setStatus("有效");
        cert.setIssueTime(LocalDateTime.now());

        CertificateEntity savedCert = certificateRepository.save(cert);

        // 4. 操作日志（真实审计）
        logService.record(
                operatorUsername,
                "审批并签发证书",
                serialNumber,
                "requestId=" + request.getRequestId() + ", user=" + user.getUsername()
        );

        return savedCert;
    }


    // 查询证书状态
    public CertificateEntity getCertificateById(Integer certId){
        return certificateRepository.findById(certId).orElse(null);
    }

    // 根据当前时间与证书生效时间判断证书状态
    public String evaluateCertificateStatus(CertificateEntity cert){
        String result;

        if(CRLRepository.existsByCertificate(cert)){
            result = "已吊销";
        }else{
            LocalDateTime now = LocalDateTime.now();
            if(now.isBefore(cert.getValidFrom())){
                result = "未生效";
            }
            else if(now.isAfter(cert.getValidTo())){
                result = "已过期";
            }
            else{
                result = "有效";
            }
        }

        // 记录查询的操作日志（证书状态查询）
        logService.record(
                "System",                         // 此处暂时先写死，后续可替换为登录用户
                "查询证书状态",
                cert.getSerialNumber(),
                "状态结果：" + result
        );


        return result;
    }

    // 按照证书序列号查询证书状态接口
    public CertificateEntity getCertificateBySerialNumber(String serialNumber){
        return certificateRepository.findBySerialNumber(serialNumber).orElse(null);
    }
}
