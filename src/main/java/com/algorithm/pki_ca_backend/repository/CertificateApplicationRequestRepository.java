package com.algorithm.pki_ca_backend.repository;

import com.algorithm.pki_ca_backend.entity.CertificateApplicationRequestEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface CertificateApplicationRequestRepository
        extends JpaRepository<CertificateApplicationRequestEntity, Long> {

    List<CertificateApplicationRequestEntity> findByStatus(String Status);

}

