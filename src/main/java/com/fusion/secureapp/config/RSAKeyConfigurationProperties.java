package com.fusion.secureapp.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@ConfigurationProperties(prefix = "rsa")
@Data
public class RSAKeyConfigurationProperties {
    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;
}
