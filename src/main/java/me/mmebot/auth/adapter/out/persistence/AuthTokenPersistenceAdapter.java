package me.mmebot.auth.adapter.out.persistence;

import java.util.Optional;
import lombok.RequiredArgsConstructor;
import me.mmebot.auth.application.port.out.LoadRefreshTokenPort;
import me.mmebot.auth.application.port.out.SaveRefreshTokenPort;
import me.mmebot.auth.domain.AuthToken;
import me.mmebot.auth.repository.AuthTokenRepository;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AuthTokenPersistenceAdapter implements LoadRefreshTokenPort, SaveRefreshTokenPort {

    private final AuthTokenRepository authTokenRepository;

    @Override
    public Optional<AuthToken> loadByUserIdAndToken(Long userId, String token) {
        return authTokenRepository.findByUserIdAndToken(userId, token);
    }

    @Override
    public AuthToken save(AuthToken authToken) {
        return authTokenRepository.save(authToken);
    }
}
