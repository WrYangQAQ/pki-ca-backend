package com.algorithm.pki_ca_backend.controller;


import com.algorithm.pki_ca_backend.dto.ApiResponse;
import com.algorithm.pki_ca_backend.dto.LoginChallenge;
import com.algorithm.pki_ca_backend.dto.LoginRequest;
import com.algorithm.pki_ca_backend.dto.LoginVerifyRequest;
import com.algorithm.pki_ca_backend.entity.UserEntity;
import com.algorithm.pki_ca_backend.service.ChallengeService;
import com.algorithm.pki_ca_backend.service.UserService;
import com.algorithm.pki_ca_backend.util.JwtUtil;
import com.algorithm.pki_ca_backend.util.RsaSignatureUtil;
import org.springframework.web.bind.annotation.*;

import java.util.List;

import static com.algorithm.pki_ca_backend.util.RsaSignatureUtil.sha256Hex;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;
    private final ChallengeService challengeService;

    public UserController(UserService userService, ChallengeService challengeService) {
        this.userService = userService;
        this.challengeService = challengeService;
    }

    // 查询所有用户
    @GetMapping
    public List<UserEntity> getAllUsers() {
        return userService.getAllUsers();
    }

    // 用户注册
    @PostMapping("/register")
    public ApiResponse<UserEntity> register(@RequestBody UserEntity user) {

        UserEntity saved = userService.registerUser(user);

        if (saved == null) {
            return ApiResponse.fail("用户名已存在");
        }

        return ApiResponse.success(saved);
    }

    @PostMapping("/auth/challenge")
    public ApiResponse<String> getChallenge(@RequestBody LoginRequest req) {

        UserEntity user = userService.findByUsername(req.getUsername());
        if (user == null) {
            return ApiResponse.fail("用户不存在");
        }

        LoginChallenge lc = challengeService.generate(req.getUsername());
        return ApiResponse.success(lc.getChallenge());
    }

    @PostMapping("/auth/login")
    public ApiResponse<String> loginBySignature(@RequestBody LoginVerifyRequest req) throws Exception {

        // 1) 用户存在性校验
        UserEntity user = userService.findByUsername(req.getUsername());
        if (user == null) {
            return ApiResponse.fail("用户不存在");
        }

        // 2) 从服务端获取 challenge
        LoginChallenge lc = challengeService.get(req.getUsername());
        if (lc == null || lc.isExpired()) {
            return ApiResponse.fail("challenge无效或已过期");
        }

        String challenge = lc.getChallenge();

//        System.out.println("SERVER CHALLENGE = [" + challenge + "]");
//        System.out.println("SERVER SHA256    = " + sha256Hex(challenge));
//        System.out.println("VERIFY CHALLENGE RAW = [" + req.getChallenge() + "]");


        // 3) 公钥验签（用服务端保存的 challenge）
        try {
            var publicKey = RsaSignatureUtil.parseRsaPublicKey(user.getLoginPublicKey());

            boolean verified = RsaSignatureUtil.verifySha256WithRsa(
                    publicKey,
                    challenge,
                    req.getSignature()
            );

            if (!verified) {
                return ApiResponse.fail("签名验证失败");
            }

            // 4) 一次性消费 challenge
            challengeService.consume(req.getUsername());

            // 5) 签发 JWT
            String token = JwtUtil.generateToken(req.getUsername(),user.getRole());

            return ApiResponse.success(token);

        } catch (Exception e) {
            return ApiResponse.fail("验签异常：" + e.getMessage());
        }
    }

}
