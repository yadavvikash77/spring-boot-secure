package com.fusion.secureapp.service;

import org.springframework.security.core.Authentication;

public interface SecureAppService {
    public String generateToken(Authentication authentication);
}
