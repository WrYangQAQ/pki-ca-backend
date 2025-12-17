package com.algorithm.pki_ca_backend.service;

import com.algorithm.pki_ca_backend.entity.CRLEntity;
import com.algorithm.pki_ca_backend.entity.CertificateEntity;
import com.algorithm.pki_ca_backend.repository.CRLRepository;
import com.algorithm.pki_ca_backend.repository.CertificateRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.List;

@Service
public class CRLService {

    @Autowired
    private CRLRepository crlRepository;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private OperationLogService logService;

    // 查询吊销记录
    public List<CRLEntity> getAllRevokedCertificates() {
        return crlRepository.findAll();
    }

    // 吊销证书(此处为旧吊销接口使用方法，为了维持系统稳定，此处仍然抛出RuntimeExcpetion，不进行ApiResponse的更改)
    public CRLEntity revokeCertificate(Integer certId, String reason) {
        CertificateEntity cert = certificateRepository.findById(certId)
                .orElseThrow(() -> new RuntimeException("证书不存在，无法吊销！"));

        CRLEntity crl = new CRLEntity();

        try {
            if ("吊销".equals(cert.getStatus())) {
                return null;
            }

            cert.setStatus("吊销");
            certificateRepository.save(cert);

            crl.setCertificate(cert);
            crl.setReason(reason);
            crl.setRevokeTime(LocalDateTime.now());
            crlRepository.save(crl);

            logService.record("System", "吊销证书", cert.getSerialNumber(), "原因：" + reason);
            return crl;

        } catch (RuntimeException e) {
            logService.record("System", "吊销证书失败", cert.getSerialNumber(), e.getMessage());
            throw e;
        }
    }
}
