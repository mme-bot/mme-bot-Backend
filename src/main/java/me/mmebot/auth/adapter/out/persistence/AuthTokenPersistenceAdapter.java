package me.mmebot.auth.adapter.out.persistence;

import jakarta.persistence.EntityManager;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import me.mmebot.auth.application.port.out.persistence.RefreshTokenPort;
import me.mmebot.auth.domain.AuthToken;
import me.mmebot.auth.domain.AuthTokenEntity;
import me.mmebot.auth.repository.AuthTokenRepository;
import me.mmebot.user.domain.UserEntity;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AuthTokenPersistenceAdapter implements RefreshTokenPort {

    private final AuthTokenRepository authTokenRepository;
    private final EntityManager entityManager;

    @Override
    public Optional<AuthToken> loadByUserIdAndToken(Long userId, String token) {
        return authTokenRepository.findByUserIdAndToken(userId, token)
                .map(AuthTokenEntity::toModel);
    }

    @Override
    public AuthToken save(AuthToken authToken) {
        UserEntity userReference = entityManager.getReference(UserEntity.class, authToken.getUserId());
        AuthTokenEntity entity = AuthTokenEntity.from(authToken, userReference);
        return authTokenRepository.save(entity).toModel();
    }
}
