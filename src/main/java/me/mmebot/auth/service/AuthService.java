package me.mmebot.auth.service;

import jakarta.transaction.Transactional;

import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.auth.domain.AuthToken;
import me.mmebot.auth.domain.AuthTokenType;
import me.mmebot.auth.domain.Role;
import me.mmebot.auth.domain.RoleName;
import me.mmebot.auth.domain.token.TokenCipher;
import me.mmebot.auth.exception.AuthException;
import me.mmebot.auth.jwt.JwtPayload;
import me.mmebot.auth.jwt.JwtProcessingException;
import me.mmebot.auth.jwt.JwtTokenService;
import me.mmebot.auth.repository.AuthTokenRepository;
import me.mmebot.auth.repository.RoleRepository;
import me.mmebot.auth.service.AuthServiceRecords.ClientMetadata;
import me.mmebot.auth.service.AuthServiceRecords.SignInResult;
import me.mmebot.auth.service.AuthServiceRecords.SignUpCommand;
import me.mmebot.auth.service.AuthServiceRecords.TokenPair;
import me.mmebot.core.service.EncryptionContextFactory;
import me.mmebot.user.domain.User;
import me.mmebot.user.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final AuthTokenRepository authTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenService jwtTokenService;
    private final TokenHashService tokenHashService;
    private final EncryptionContextFactory encryptionContextFactory;
    private final EmailVerificationService emailVerificationService;
    private final TokenCipher tokenCipher;

    public SignInResult signIn(String email, String rawPassword, ClientMetadata metadata) {
        String normalizedEmail = normalizeEmail(email);
        log.info("Attempting sign-in for {}", normalizedEmail);
        User user = userRepository.findByEmail(normalizedEmail)
                .orElseThrow(() -> {
                    log.warn("Sign-in failed: no user found for {}", normalizedEmail);
                    return AuthException.invalidCredentials();
                });

        if (user.isDeleted()) {
            log.warn("Sign-in failed: user {} is marked as deleted", user.getId());
            throw AuthException.invalidCredentials(); // 삭제한 유저인 거 굳이 웹에 보여줄 필요 없음
        }
        if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
            log.warn("Sign-in failed: invalid credentials for {}", normalizedEmail);
            throw AuthException.invalidCredentials();
        }

        List<RoleName> roles = roleRepository.findByUserId(user.getId()).stream()
                .map(Role::getRoleName)
                .toList();

        TokenPair tokens = issueTokens(user, roles, metadata);
        Long botId = user.getBot() != null ? user.getBot().getId() : null;
        log.info("Sign-in succeeded for user {}", user.getId());
        return new SignInResult(user.getId(), botId, user.getNickname(), tokens.accessToken(), tokens.refreshToken());
    }

    @Transactional
    public void signUp(SignUpCommand command) {
        String normalizedEmail = normalizeEmail(command.email());
        log.info("Attempting sign-up for {}", normalizedEmail);
        userRepository.findByEmail(normalizedEmail)
                .ifPresent(existing -> {
                    log.warn("Sign-up failed: {} already in use", normalizedEmail);
                    throw AuthException.duplicateEmail();
                });

        emailVerificationService.requireVerified(command.emailVerificationId(), normalizedEmail);

        User user = User.builder()
                .email(normalizedEmail)
                .password(passwordEncoder.encode(command.password()))
                .nickname(command.nickname().trim())
                .sns(false)
                .encryptionContext(encryptionContextFactory.createContext(tokenHashService.hash(normalizedEmail)))
                .build();

        User saved = userRepository.save(user);
        if (!roleRepository.existsByUserIdAndRoleName(saved.getId(), RoleName.ROLE_USER)) {
            roleRepository.save(Role.builder()
                    .user(saved)
                    .roleName(RoleName.ROLE_USER)
                    .build());
        }
        log.info("Sign-up succeeded: user {} registered", saved.getId());
    }

    public TokenPair reissue(Long userId, String refreshToken, ClientMetadata metadata) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.warn("Token reissue failed: user {} not found", userId);
                    return AuthException.userNotFound();
                });
        if (user.isDeleted()) {
            log.warn("Token reissue failed: user {} is marked as deleted", userId);
            throw AuthException.deletedAccount();
        }

        AuthToken authToken = authTokenRepository.findByUserIdAndToken(userId, refreshToken)
                .orElseThrow(() -> {
                    log.warn("Token reissue failed: user's {} token not found", userId);
                    return AuthException.tokenNotFound();
                });

        String decodedToken = authToken.getDecodeToken(userId.toString(), tokenCipher, tokenHashService);
        JwtPayload storedPayload = parseToken(decodedToken);
        if (!Objects.equals(storedPayload.userId(), userId)) {
            log.warn("Token reissue failed: refresh token user mismatch (expected {}, actual {})", userId,
                    storedPayload.userId());
            throw AuthException.refreshTokenUserMismatch();
        }
        if (storedPayload.tokenType() != AuthTokenType.REFRESH) {
            log.warn("Token reissue failed: invalid token type {} for user {}", storedPayload.tokenType(), userId);
            throw AuthException.invalidTokenType();
        }

        byte[] userHash = hashUserTag(userId);

        AuthToken storedToken = authTokenRepository.findByUserIdAndEncryptionContextAadHash(userId, userHash)
                .orElseThrow(() -> {
                    log.warn("Token reissue failed: refresh token missing for user {}", userId);
                    return AuthException.refreshTokenMissing();
                });

        OffsetDateTime now = OffsetDateTime.now();
        if (storedToken.isRevoked() || storedToken.isExpired(now)) {
            log.warn("Token reissue failed: refresh token invalid for user {}", userId);
            throw AuthException.refreshTokenInvalid();
        }

        storedToken.revoke(now);
        authTokenRepository.save(storedToken);

        List<RoleName> roles = roleRepository.findByUserId(userId).stream()
                .map(Role::getRoleName)
                .toList();

        TokenPair tokenPair = issueTokens(user, roles, metadata);
        log.info("Token reissue succeeded for user {}", userId);
        return tokenPair;
    }

    private TokenPair issueTokens(User user, Collection<RoleName> roleNames, ClientMetadata metadata) {
        Collection<RoleName> effectiveRoles = roleNames.isEmpty()
                ? List.of(RoleName.ROLE_USER)
                : roleNames;

        /**
         * TODO Access token 암호화 후, Redis 에 저장하는 로직 추가 필요
         */
        String accessToken = jwtTokenService.createAccessToken(user.getId(), effectiveRoles);
        String refreshToken = jwtTokenService.createRefreshToken(user.getId(), effectiveRoles);
        AuthToken authToken = storeRefreshToken(user, refreshToken, metadata);
        log.debug("Issued tokens for user {} with roles {}", user.getId(), effectiveRoles);
        return new TokenPair(accessToken, authToken.getToken());
    }

    private AuthToken storeRefreshToken(User user, String refreshToken, ClientMetadata metadata) {
        JwtPayload payload = parseToken(refreshToken);
        byte[] userHash = hashUserTag(user.getId());
        AuthToken authToken = new AuthToken(
                user,
                payload.tokenType(),
                refreshToken,
                payload.expiresAt(),
                metadata != null ? metadata.ipAddress() : null,
                metadata != null ? metadata.userAgent() : null,
                tokenCipher,
                tokenHashService,
                userHash
        );
        authTokenRepository.save(authToken);
        log.debug("Stored refresh token metadata for user {}", user.getId());

        return authToken;
    }

    private JwtPayload parseToken(String token) {
        try {
            return jwtTokenService.parse(token);
        } catch (JwtProcessingException ex) {
            log.error("Token parsing failed", ex);
            throw AuthException.tokenProcessingFailed("Failed to process token", ex);
        }
    }

    private byte[] hashUserTag(Long userId) {
        if (userId == null) {
            log.error("Token processing failed: missing user identifier for hashing");
            throw AuthException.tokenProcessingFailed("Refresh token identifier is missing", new IllegalStateException("userId"));
        }
        return tokenHashService.hash(String.valueOf(userId));
    }

    private String normalizeEmail(String email) {
        if (email == null) {
            log.error("Email normalization failed: email is required");
            throw AuthException.emailRequired();
        }
        return email.trim().toLowerCase();
    }
}
