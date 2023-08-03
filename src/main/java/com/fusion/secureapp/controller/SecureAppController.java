package com.fusion.secureapp.controller;

import com.fusion.secureapp.service.SecureAppService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class SecureAppController {

    private SecureAppService secureAppService;

    @PostMapping("/token")
    public ResponseEntity<String> generateToken(Authentication authentication) {
        return ResponseEntity.ok(secureAppService.generateToken(authentication));
    }
}
