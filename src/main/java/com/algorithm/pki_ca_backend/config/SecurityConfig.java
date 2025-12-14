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
                                "/api/certificates/status",
                                "/api/certificates/*/status",
                                "/api/certificates/*/verify",
                                "/api/crl"
                        ).permitAll()

                        // 证书查询，下载接口 允许登录用户访问
                        .requestMatchers(
                                "/api/certificates",
                                "/api/crl/revoke",
                                "/api/certificates/apply",
                                "/api/certificates/{certId}/download"
                        ).hasAnyRole("USER","ADMIN")

                        // 证书注册 & 日志，用户信息查询接口 允许管理员访问
                        .requestMatchers(
                                "/api/certificates/issue",
                                "/api/certificates/requests",
                                "/api/logs",
                                "/api/users"
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
