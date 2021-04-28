package com.mandaeauth.core;

import com.mandaeauth.domain.Usuario;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.Collections;

@Getter
public class AuthUser extends User {

    private Long userId;
    private String fullName;
    private String email;

    public AuthUser(Usuario usuario, Collection<? extends GrantedAuthority> authotiries) {
        super(usuario.getEmail(), usuario.getSenha(), authotiries);

        this.userId = usuario.getId();
        this.fullName = usuario.getNome();
    }
}
