package me.mmebot.auth.application.port.out;

import java.time.Duration;
import java.util.Collection;
import me.mmebot.auth.domain.RoleName;

public interface JwtIssuePort {
    String createAccessToken(Long userId, Collection<RoleName> roles);
    String createRefreshToken(Long userId, Collection<RoleName> roles);
    Duration accessTokenExpiry();
}
