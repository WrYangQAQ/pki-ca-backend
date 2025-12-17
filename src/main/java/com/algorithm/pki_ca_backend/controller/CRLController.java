package com.algorithm.pki_ca_backend.controller;

import com.algorithm.pki_ca_backend.dto.ApiResponse;
import com.algorithm.pki_ca_backend.entity.CRLEntity;
import com.algorithm.pki_ca_backend.service.CRLService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/crl")
public class CRLController{

    @Autowired
    private CRLService crlService;

    // 查询所有吊销记录
    @GetMapping
    public ApiResponse<List<CRLEntity>> getAllRevokedCertificates(){
        List<CRLEntity> list = crlService.getAllRevokedCertificates();
        return ApiResponse.success(list);
    }

    // 吊销证书(！！！旧吊销接口，不再使用)
    @PostMapping("/revoke")
    public ApiResponse<CRLEntity> revokeCertificate(@RequestBody Map<String, Object> payload){

        Integer certId = (Integer) payload.get("certId");
        String reason = (String) payload.get("reason");

        if(certId == null || reason == null || reason.isBlank()){
            return ApiResponse.fail("参数不完整");
        }

        CRLEntity crl = crlService.revokeCertificate(certId, reason);

        if(crl == null){
            return ApiResponse.fail("证书不存在或已被吊销");
        }

        return ApiResponse.success(crl);
    }
}
