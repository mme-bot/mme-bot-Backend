package me.mmebot.auth.adapter.out.persistence;

import java.util.Optional;
import lombok.RequiredArgsConstructor;
import me.mmebot.auth.application.port.out.LoadRefreshTokenPort;
import me.mmebot.auth.application.port.out.SaveRefreshTokenPort;
import me.mmebot.auth.domain.AuthTokenEntity;
import me.mmebot.auth.repository.AuthTokenRepository;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AuthTokenPersistenceAdapter implements LoadRefreshTokenPort, SaveRefreshTokenPort {

    private final AuthTokenRepository authTokenRepository;

    @Override
    public Optional<AuthTokenEntity> loadByUserIdAndToken(Long userId, String token) {
        return authTokenRepository.findByUserIdAndToken(userId, token);
    }

    @Override
    public AuthTokenEntity save(AuthTokenEntity authToken) {
        return authTokenRepository.save(authToken);
    }
}
