package com.mandaeauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients
                .inMemory()
                    .withClient("mandae-web")
                    .secret(passwordEncoder.encode("123"))
                    .authorizedGrantTypes("password", "refresh_token")
                    .scopes("write", "read")
                    .accessTokenValiditySeconds(60 * 60 * 6)// 6 horas (padrão é 12 horas);

                //Authorization Code Grant Type
                .and()
                    .withClient("analytics")
                    .secret(passwordEncoder.encode("123"))
                    .authorizedGrantTypes("authorization_code")
                    .redirectUris("http://localhost:8082")
                    .scopes("write", "read")

                //Client Credentials Flow
                .and()
                    .withClient("faturamento")
                    .secret(passwordEncoder.encode("123"))
                    .authorizedGrantTypes("client_credentials")
                    .scopes("write", "read")

                .and()
                    .withClient("checktoken")
                    .secret(passwordEncoder.encode("check123"));
    }

    //Para o PasswordFlow, precisamos desse método
    @Override public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService);
    }

    @Override public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.checkTokenAccess("isAuthenticated()");
        //security.checkTokenAccess("permitAll()");
    }
}
