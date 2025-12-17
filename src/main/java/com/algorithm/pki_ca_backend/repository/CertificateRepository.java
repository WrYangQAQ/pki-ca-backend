package com.algorithm.pki_ca_backend.repository;

import com.algorithm.pki_ca_backend.entity.CertificateEntity;

import java.util.List;
import java.util.Optional;

import com.algorithm.pki_ca_backend.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CertificateRepository extends JpaRepository<CertificateEntity, Integer> {
    boolean existsBySerialNumber(String serialNumber);
    Optional<CertificateEntity> findBySerialNumber(String serialNumber);
    List<CertificateEntity> findByUser(UserEntity user);
}
