package me.mmebot.auth.security;

import org.springframework.security.core.userdetails.UserDetails;

public final class SecurityUtil {

    private SecurityUtil() {}

    public static Long extractUserId(UserDetails principal) {
        if (principal instanceof CustomUserDetails cud) {
            return cud.getUser().getId();
        }
        throw new IllegalStateException("Unsupported principal type: " + (principal != null ? principal.getClass() : null));
    }
}

