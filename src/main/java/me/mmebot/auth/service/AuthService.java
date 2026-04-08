package me.mmebot.auth.service;

import jakarta.transaction.Transactional;

import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import lombok.RequiredArgsConstructor;
import me.mmebot.auth.domain.AuthTokenEntity;
import me.mmebot.auth.domain.AuthTokenType;
import me.mmebot.auth.domain.RoleEntity;
import me.mmebot.auth.domain.RoleName;
import me.mmebot.auth.domain.token.EncryptedToken;
import me.mmebot.auth.exception.AuthException;
import me.mmebot.auth.jwt.JwtPayload;
import me.mmebot.auth.jwt.JwtProcessingException;
import me.mmebot.auth.jwt.JwtTokenService;
import me.mmebot.auth.repository.AuthTokenRepository;
import me.mmebot.auth.repository.RoleRepository;
import me.mmebot.auth.security.CustomUserDetails;
import me.mmebot.auth.security.CustomUserDetailsService;
import me.mmebot.auth.service.AuthServiceRecords.ClientMetadata;
import me.mmebot.auth.service.AuthServiceRecords.SignInResult;
import me.mmebot.auth.service.AuthServiceRecords.SignUpCommand;
import me.mmebot.auth.service.AuthServiceRecords.TokenPair;
import me.mmebot.common.logging.Masked;
import me.mmebot.core.domain.EncryptionContextEntity;
import me.mmebot.core.service.EncryptionContextFactory;
import me.mmebot.user.domain.UserEntity;
import me.mmebot.user.repository.UserRepository;
import me.mmebot.user.service.UserEmailProtector;
import me.mmebot.user.service.UserEmailProtector.EmailSecrets;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Transactional
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final AuthTokenRepository authTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenService jwtTokenService;
    private final TokenHashService tokenHashService;
    private final EncryptionContextFactory encryptionContextFactory;
    private final RedisService redisService;
    private final TokenCiperService tokenCiperService;
    private final EncryptionContextService encryptionContextService;
    private final CustomUserDetailsService customUserDetailsService;
    private final UserEmailProtector userEmailProtector;

    public SignInResult signIn(String email, @Masked String rawPassword, ClientMetadata metadata) {
        String normalizedEmail = normalizeEmail(email);
        CustomUserDetails userDetails;
        try {
            userDetails = (CustomUserDetails) customUserDetailsService.loadUserByUsername(email);
        } catch (UsernameNotFoundException ex) {
            throw AuthException.invalidCredentials();
        }

        UserEntity user = userDetails.getUser();
        if (user.isDeleted()) {
            throw AuthException.deletedAccount();
        }
        if (!passwordEncoder.matches(rawPassword, userDetails.getPassword())) {
            throw AuthException.invalidCredentials();
        }

        List<RoleName> roles = userDetails.getRoleNames();

        TokenPair tokens = issueTokens(user, roles, metadata);
        Long botId = user.getBot() != null ? user.getBot().getId() : null;
        return new SignInResult(user.getId(), botId, user.getNickname(), tokens.accessToken(), tokens.refreshToken());
    }

    public void logout(Long userId, @Masked String refreshToken) {
        if (userId == null) {
            throw AuthException.authenticationRequired();
        }
        if (refreshToken == null || refreshToken.isBlank()) {
            throw AuthException.refreshTokenMissing();
        }

        authTokenRepository.findByUserIdAndToken(userId, refreshToken)
                .ifPresentOrElse(token -> {
                    if (token.isRevoked()) {
                        return;
                    }
                    token.revoke(OffsetDateTime.now());
                }, () -> {});
    }

    private String getNormalizedEmail(String email) {
        return email.toLowerCase().trim();
    }

    public void signUp(SignUpCommand command) {
        String normalizedEmail = getNormalizedEmail(command.email());
        byte[] emailAadHash = userEmailProtector.aadHash(normalizedEmail);
        userRepository.findByEmailEncryptionContextAadHash(emailAadHash)
                .ifPresent(_ -> {
                    throw AuthException.duplicateEmail();
                });

        EmailSecrets emailSecrets = userEmailProtector.prepare(normalizedEmail, emailAadHash);
        EncryptionContextEntity encryptionContext = encryptionContextFactory.createContext(emailAadHash);
        UserEntity user = UserEntity.builder()
                .emailCipher(emailSecrets.emailCipher())
                .emailHash(emailSecrets.emailHash())
                .password(passwordEncoder.encode(command.password()))
                .nickname(command.nickname().trim())
                .sns(false)
                .emailEncryptionContext(encryptionContext)
                .build();

        UserEntity saved = userRepository.save(user);
        if (!roleRepository.existsByUserIdAndRoleName(saved.getId(), RoleName.ROLE_USER)) {
            roleRepository.save(RoleEntity.builder()
                    .user(saved)
                    .roleName(RoleName.ROLE_USER)
                    .build());
        }
    }

    public TokenPair reissue(Long userId, @Masked String refreshToken, ClientMetadata metadata) {
        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> AuthException.userNotFound());
        if (user.isDeleted()) {
            throw AuthException.deletedAccount();
        }

        byte[] userHash = tokenHashService.hash(userId.toString());
        AuthTokenEntity authToken = authTokenRepository.findByUserIdAndToken(userId, refreshToken)
                .orElseThrow(() -> AuthException.tokenNotFound());

        // 토큰 타입이 refresh 타입이 아님
        if (!authToken.getType().equals(AuthTokenType.REFRESH)) {
            throw AuthException.refreshTokenMissing();
        }

        // 시간 지남
        OffsetDateTime now = OffsetDateTime.now();
        if (authToken.isRevoked() || authToken.isExpired(now)) {
            throw AuthException.refreshTokenInvalid();
        }

        // hash 다륾
        if (!Arrays.equals(userHash, authToken.getEncryptionContext().getAadHash())) {
            authToken.revoke(now);
            throw AuthException.refreshTokenInvalid();
        }

        String decodedToken = tokenCiperService.getDecodeToken(authToken.getToken(), authToken.getEncryptionContext(), authToken.getType(), userId.toString());
        JwtPayload storedPayload = parseToken(decodedToken);
        if (!Objects.equals(storedPayload.userId(), userId)) {
            authToken.revoke(now);
            throw AuthException.refreshTokenUserMismatch();
        }
        if (storedPayload.tokenType() != AuthTokenType.REFRESH) {
            throw AuthException.invalidTokenType();
        }

        /**
         * 인증 완료 되었으므로 새 토큰 만들기
         */
        List<RoleName> roles = roleRepository.findByUserId(userId).stream()
                .map(RoleEntity::getRoleName)
                .toList();

        TokenPair tokenPair = issueTokens(user, roles, metadata);
        return tokenPair;
    }

    private TokenPair issueTokens(UserEntity user, Collection<RoleName> roleNames, ClientMetadata metadata) {
        Collection<RoleName> effectiveRoles = roleNames.isEmpty()
                ? List.of(RoleName.ROLE_USER)
                : roleNames;

        String accessToken = jwtTokenService.createAccessToken(user.getId(), effectiveRoles);
        String refreshToken = jwtTokenService.createRefreshToken(user.getId(), effectiveRoles);
        AuthTokenEntity authToken = storeRefreshToken(user, refreshToken, metadata);

        // 암호화 후 redis 저장
        EncryptedToken encryptAccessToken = getEncryptAccessToken(user, accessToken);
        storeAccessTokenToRedis(user.getId(), encryptAccessToken.payload());

        return new TokenPair(accessToken, authToken.getToken());
    }

    private EncryptedToken getEncryptAccessToken(UserEntity user, String accessToken) {
        EncryptedToken encryptAccessToken = tokenCiperService.getEncryptedToken(accessToken, user.getId(), null);
        encryptionContextService.save(encryptAccessToken.context());
        return encryptAccessToken;
    }

    private void storeAccessTokenToRedis(Long userId, String accessToken) {
        String key = "jwt:" + userId;
        redisService.enqueueRedis(key, accessToken, jwtTokenService.getAccessTokenExpiry());
    }

    private AuthTokenEntity storeRefreshToken(UserEntity user, String refreshToken, ClientMetadata metadata) {
        JwtPayload payload = parseToken(refreshToken);
        EncryptedToken encryptedToken = tokenCiperService.getEncryptedToken(
                refreshToken,
                user.getId(),
                null
        );
        AuthTokenEntity authToken = new AuthTokenEntity(
                user,
                payload.tokenType(),
                encryptedToken.payload(),
                encryptedToken.context(),
                payload.expiresAt(),
                metadata != null ? metadata.ipAddress() : null,
                metadata != null ? metadata.userAgent() : null
        );
        authTokenRepository.save(authToken);

        return authToken;
    }

    private JwtPayload parseToken(String token) {
        try {
            return jwtTokenService.parse(token);
        } catch (JwtProcessingException ex) {
            throw AuthException.tokenProcessingFailed("Failed to process token", ex);
        }
    }

    private String normalizeEmail(String email) {
        if (email == null) {
            throw AuthException.emailRequired();
        }
        return email.trim().toLowerCase();
    }
}
