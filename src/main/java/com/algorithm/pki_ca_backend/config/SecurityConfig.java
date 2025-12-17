package com.algorithm.pki_ca_backend.config;

import com.algorithm.pki_ca_backend.config.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm ->
                        sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(new RestAuthenticationEntryPoint())
                        .accessDeniedHandler(new RestAccessDeniedHandler())
                )
                .authorizeHttpRequests(auth -> auth
                        // 用户登录与注册接口 允许所有人访问
                        .requestMatchers(
                                "/api/users/auth/challenge",
                                "/api/users/auth/login",
                                "/api/users/register"
                        ).permitAll()

                        // 公共证书 & CRL 查询接口 允许所有人访问
                        .requestMatchers(
                                "/api/certificates/status",                  // 根据SerialNumber查询证书状态
                                "/api/certificates/{certId}/status",         // 根据ID查询证书状态
                                "/api/certificates/{serialNumber}/verify",   // 根据SerialNumber查询证书状态(更详细)
                                "/api/crl"                                   // 查询吊销列表
                        ).permitAll()

                        // 证书查询，下载接口 允许登录用户访问
                        .requestMatchers(
                                "/api/certificates/{certId}/download",                 // 根据证书id下载证书
                                "/api/certificates/apply-request",                     // 申请证书签发接口(发一个申请请求)
                                "/api/certificates/{serialNumber}/revoke-request",     // 申请证书吊销接口
                                "/api/certificates/my"                                 // 查看自己的证书接口
                        ).hasAnyRole("USER","ADMIN")

                        // 证书注册 & 日志，用户信息查询接口 允许管理员访问
                        .requestMatchers(
                                "/api/crl/revoke",                                  // 旧吊销接口，不使用(安全起见放在ADMIN)
                                "/api/certificates/issue",                          // 旧签发接口，不使用(安全起见放在ADMIN)
                                "/api/certificates",                                // 查询所有证书的状态
                                "/api/logs",                                        // 管理员查询日志
                                "/api/users",                                       // 管理员查询用户信息
                                "/api/certificates/apply-requests",                 // 管理员查询证书申请请求列表
                                "/api/certificates/apply-requests/{id}/approve",    // 管理员通过申请请求，签发证书
                                "/api/certificates/apply-requests/{id}/reject",     // 管理员拒绝申请请求
                                "/api/certificates/revoke-requests",                // 管理员查询证书吊销请求列表
                                "/api/certificates/revoke-requests/{id}/approve",   // 管理员通过吊销申请
                                "/api/certificates/revoke-requests/{id}/reject"     // 管理员拒绝吊销申请
                        ).hasRole("ADMIN")

                        // 兜底（用户权限接口）
                        .anyRequest().authenticated()         // 即其余接口必须登录
                )
                .addFilterBefore(
                        new JwtAuthenticationFilter(),
                        UsernamePasswordAuthenticationFilter.class
                );

        return http.build();
    }
}
