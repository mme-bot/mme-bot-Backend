package me.mmebot.auth.jwt;

import java.util.Collection;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private final Long principal;
    private final String credentials;

    public JwtAuthenticationToken(Long principal,
                                  Collection<? extends GrantedAuthority> authorities,
                                  String credentials) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        setAuthenticated(true);
    }

    @Override
    public Long getPrincipal() {
        return principal;
    }

    @Override
    public String getCredentials() {
        return credentials;
    }
}
