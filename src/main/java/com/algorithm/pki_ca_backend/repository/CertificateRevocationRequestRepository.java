package com.algorithm.pki_ca_backend.repository;

import com.algorithm.pki_ca_backend.entity.CertificateRevocationRequestEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface CertificateRevocationRequestRepository
        extends JpaRepository<CertificateRevocationRequestEntity, Long> {

    List<CertificateRevocationRequestEntity> findByStatus(String Status);
}
