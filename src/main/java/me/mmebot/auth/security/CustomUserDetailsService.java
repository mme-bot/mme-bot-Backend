package me.mmebot.auth.security;

import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.auth.application.port.out.persistence.LoadUserRolesPort;
import me.mmebot.auth.application.port.out.persistence.UserPersistencePort;
import me.mmebot.auth.domain.RoleName;
import me.mmebot.user.domain.NormalizedEmail;
import me.mmebot.user.domain.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserPersistencePort userPersistencePort;
    private final LoadUserRolesPort loadUserRolesPort;

    @Override
    public UserDetails loadUserByUsername(String username) {
        NormalizedEmail normalizedEmail = normalize(username);
        User user = userPersistencePort.loadByNormalizedEmail(normalizedEmail.value())
                .orElseThrow(() -> {
                    log.warn("User lookup failed: {} not found", normalizedEmail);
                    return new UsernameNotFoundException("User not found");
                });

        List<RoleName> roles = loadUserRolesPort.loadRoleNames(user.getId());
        log.debug("Loaded user {} with {} roles", user.getId(), roles.size());
        return CustomUserDetails.of(user, roles);
    }

    private NormalizedEmail normalize(String email) {
        try {
            return NormalizedEmail.from(email);
        } catch (IllegalArgumentException e) {
            throw new UsernameNotFoundException("Email must not be blank");
        }
    }
}
