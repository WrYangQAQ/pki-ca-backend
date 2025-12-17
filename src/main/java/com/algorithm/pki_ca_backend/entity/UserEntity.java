package com.algorithm.pki_ca_backend.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "Users")
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "UserID")
    private Integer userId;

    @Column(name = "Username", nullable = false, unique = true, length = 50)
    private String username;

    @Column(name = "Email", length = 100)
    private String email;

    // nvarchar(max)
    @Column(name = "LoginPublicKey", columnDefinition = "nvarchar(max)", nullable = false)
    private String loginPublicKey;

    @Column(name = "RegisterTime")
    private LocalDateTime registerTime;

    @Column(name = "Role", nullable = false)
    private String role;
}
