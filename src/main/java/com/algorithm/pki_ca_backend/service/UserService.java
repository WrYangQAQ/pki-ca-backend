package com.algorithm.pki_ca_backend.service;

import com.algorithm.pki_ca_backend.entity.UserEntity;
import com.algorithm.pki_ca_backend.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class UserService {

    @Autowired
    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public List<UserEntity> getAllUsers() {
        return userRepository.findAll();
    }

    @Autowired
    public OperationLogService logService;

    public boolean exists(String username) {
        return userRepository.existsByUsername(username);
    }

    // 用户注册业务逻辑实现
    public UserEntity registerUser(UserEntity user) {
        if (userRepository.existsByUsername(user.getUsername())) {
            return null;
        }
        user.setRole("ROLE_USER");     // 注册时将用户权限设置为普通用户
        user.setRegisterTime(LocalDateTime.now());
        return userRepository.save(user);
    }

    // 根据用户名查找用户
    public UserEntity findByUsername(String username) {
        return userRepository.findByUsername(username).orElse(null);
    }

}
