package com.mandaeauth.core;

import com.mandaeauth.domain.Usuario;
import lombok.Getter;
import org.springframework.security.core.userdetails.User;

import java.util.Collections;

@Getter
public class AuthUser extends User {

    private String fullName;
    private String email;

    public AuthUser(Usuario usuario) {
        super(usuario.getEmail(), usuario.getSenha(), Collections.emptyList());
        this.fullName = usuario.getNome();
    }
}
