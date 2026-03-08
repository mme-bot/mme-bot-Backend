package me.mmebot.auth.security;

import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.auth.domain.Role;
import me.mmebot.auth.domain.RoleName;
import me.mmebot.auth.repository.RoleRepository;
import me.mmebot.user.domain.User;
import me.mmebot.user.repository.UserRepository;
import me.mmebot.user.service.UserEmailProtector;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final UserEmailProtector userEmailProtector;

    @Override
    public UserDetails loadUserByUsername(String username) {
        String normalizedEmail = normalize(username);
        byte[] aadHash = userEmailProtector.aadHash(normalizedEmail);
        User user = userRepository.findByEmailEncryptionContextAadHash(aadHash)
                .orElseThrow(() -> {
                    log.warn("User lookup failed: {} not found", normalizedEmail);
                    return new UsernameNotFoundException("User not found");
                });

        List<RoleName> roles = roleRepository.findByUserId(user.getId()).stream()
                .map(Role::getRoleName)
                .toList();

        log.debug("Loaded user {} with {} roles", user.getId(), roles.size());
        return CustomUserDetails.of(user, roles);
    }

    private String normalize(String email) {
        if (email == null) {
            throw new UsernameNotFoundException("Email must not be null");
        }
        return email.trim().toLowerCase();
    }
}
