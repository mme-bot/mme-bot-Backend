package me.mmebot.auth.security;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.experimental.FieldDefaults;
import me.mmebot.auth.domain.RoleName;
import me.mmebot.user.domain.UserEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Getter
@Builder
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
public class CustomUserDetails implements UserDetails {

    UserEntity user;
    String email;
    String password;
    boolean deleted;
    List<RoleName> roleNames;
    List<SimpleGrantedAuthority> authorities;

    public static CustomUserDetails of(UserEntity user, Collection<RoleName> roles) {
        Objects.requireNonNull(user, "user must not be null");
        List<RoleName> effectiveRoles = roles == null || roles.isEmpty()
                ? List.of(RoleName.ROLE_USER)
                : List.copyOf(roles);
        List<SimpleGrantedAuthority> grantedAuthorities = effectiveRoles.stream()
                .map(RoleName::name)
                .map(SimpleGrantedAuthority::new)
                .toList();
        String username = user.getEmailCipher();
        return CustomUserDetails.builder()
                .user(user)
                .email(username)
                .password(user.getPassword())
                .deleted(user.isDeleted())
                .roleNames(effectiveRoles)
                .authorities(grantedAuthorities)
                .build();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return !deleted;
    }
}
