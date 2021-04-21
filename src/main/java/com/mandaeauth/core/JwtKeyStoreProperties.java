package com.mandaeauth.core;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotBlank;

@Component
@Validated
@ConfigurationProperties("mandae.jwt.keystore")
public class JwtKeyStoreProperties {

    @NotBlank
    private String path;

    @NotBlank
    private String password;

    @NotBlank
    private String keyPairAlias;

    public String getPath(){
        return path;
    }

    public void setPath(String path){
        this.path = path;
    }

    public String getPassword(){
        return password;
    }

    public void setPassword(String password){
        this.password = password;
    }

    public void setKeyPairAlias(String keyPairAlias){
        this.keyPairAlias = keyPairAlias;
    }

    public String getKeyPairAlias(){
        return keyPairAlias;
    }
}
