package me.mmebot.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import me.mmebot.auth.domain.AuthToken;
import me.mmebot.auth.domain.AuthTokenType;
import me.mmebot.auth.domain.EmailVerification;
import me.mmebot.auth.domain.Role;
import me.mmebot.auth.domain.RoleName;
import me.mmebot.auth.domain.token.EncryptedToken;
import me.mmebot.auth.domain.token.TokenCipher;
import me.mmebot.auth.domain.token.TokenCipherSpec;
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
import me.mmebot.core.domain.EncryptionContext;
import me.mmebot.core.service.EncryptionContextFactory;
import me.mmebot.user.domain.User;
import me.mmebot.user.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private AuthTokenRepository authTokenRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtTokenService jwtTokenService;

    @Mock
    private TokenHashService tokenHashService;

    @Mock
    private EncryptionContextFactory encryptionContextFactory;

    @Mock
    private EmailVerificationService emailVerificationService;

    @InjectMocks
    private AuthService authService;

    @Mock
    private TokenCipher tokenCipher;

    @BeforeEach
    void setUpTokenCipher() {
        lenient().when(tokenCipher.encrypt(anyString(), any(TokenCipherSpec.class))).thenAnswer(invocation -> {
            String plain = invocation.getArgument(0);
            TokenCipherSpec spec = invocation.getArgument(1);
            byte[] aadHash = spec != null ? spec.aadHash() : null;
            EncryptionContext context = encryptionContextFactory.createContext(aadHash);
            if (context == null) {
                context = EncryptionContext.builder().aadHash(aadHash).build();
            }
            return new EncryptedToken(plain, context);
        });

        lenient().when(tokenCipher.decrypt(any(EncryptedToken.class), any(TokenCipherSpec.class)))
                .thenAnswer(invocation -> invocation.<EncryptedToken>getArgument(0).payload());
    }


    @Test
    void signIn_withValidCredentials_returnsResultAndStoresRefreshToken() {
        OffsetDateTime futureExpiry = OffsetDateTime.now().plusHours(2);
        User user = buildUser(1L, "user@example.com", "encoded-pass", null);

        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("password", "encoded-pass")).thenReturn(true);
        Role adminRole = Role.builder().roleName(RoleName.ROLE_ADMIN).build();
        when(roleRepository.findByUserId(1L)).thenReturn(List.of(adminRole));
        when(jwtTokenService.createAccessToken(eq(1L), anyCollection())).thenReturn("access-token");
        when(jwtTokenService.createRefreshToken(eq(1L), anyCollection())).thenReturn("refresh-token");
        JwtPayload refreshPayload = new JwtPayload(1L, List.of(RoleName.ROLE_ADMIN.name()), AuthTokenType.REFRESH, futureExpiry,
                "refresh-jti");
        when(jwtTokenService.parse("refresh-token")).thenReturn(refreshPayload);
        byte[] hashedJti = new byte[]{7, 7, 7};
        when(tokenHashService.hash(user.getId().toString())).thenReturn(hashedJti);
        EncryptionContext tokenContext = EncryptionContext.builder().id(99L).aadHash(hashedJti).build();
        when(encryptionContextFactory.createContext(argThat(bytes -> Arrays.equals(bytes, hashedJti))))
                .thenReturn(tokenContext);
        when(authTokenRepository.save(any(AuthToken.class))).thenAnswer(invocation -> invocation.getArgument(0));

        ClientMetadata metadata = new ClientMetadata("agent", "127.0.0.1");

        SignInResult result = authService.signIn("user@example.com", "password", metadata);

        assertThat(result.userId()).isEqualTo(1L);
        assertThat(result.botId()).isNull();
        assertThat(result.nickname()).isEqualTo(user.getNickname());
        assertThat(result.accessToken()).isEqualTo("access-token");
        assertThat(result.refreshToken()).isEqualTo("refresh-token");

        ArgumentCaptor<String> emailCaptor = ArgumentCaptor.forClass(String.class);
        verify(userRepository).findByEmail(emailCaptor.capture());
        assertThat(emailCaptor.getValue()).isEqualTo("user@example.com");

        verify(passwordEncoder).matches("password", "encoded-pass");

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Collection<RoleName>> rolesCaptor = ArgumentCaptor.forClass(Collection.class);
        verify(jwtTokenService).createAccessToken(eq(1L), rolesCaptor.capture());
        verify(jwtTokenService).createRefreshToken(eq(1L), rolesCaptor.capture());
        List<Collection<RoleName>> capturedRoles = rolesCaptor.getAllValues();
        assertThat(capturedRoles).hasSize(2);
        assertThat(capturedRoles.get(0)).containsExactly(RoleName.ROLE_ADMIN);
        assertThat(capturedRoles.get(1)).containsExactlyElementsOf(capturedRoles.get(0));

        verify(tokenHashService).hash(user.getId().toString());
        ArgumentCaptor<byte[]> contextHashCaptor = ArgumentCaptor.forClass(byte[].class);
        verify(encryptionContextFactory).createContext(contextHashCaptor.capture());
        assertThat(contextHashCaptor.getValue()).isEqualTo(hashedJti);

        ArgumentCaptor<AuthToken> tokenCaptor = ArgumentCaptor.forClass(AuthToken.class);
        verify(authTokenRepository).save(tokenCaptor.capture());
        AuthToken stored = tokenCaptor.getValue();
        assertThat(stored.getUser()).isEqualTo(user);
        assertThat(stored.getType()).isEqualTo(AuthTokenType.REFRESH);
        assertThat(stored.getExpiredAt()).isEqualTo(futureExpiry);
        assertThat(stored.getUserAgent()).isEqualTo("agent");
        assertThat(stored.getIpAddress()).isEqualTo("127.0.0.1");
        assertThat(stored.getEncryptionContext()).isEqualTo(tokenContext);
    }

    @Test
    void signIn_whenNoRoles_assignsDefaultRole() {
        OffsetDateTime futureExpiry = OffsetDateTime.now().plusHours(2);
        User user = buildUser(5L, "empty@example.com", "encoded", null);

        when(userRepository.findByEmail("empty@example.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("pw", "encoded")).thenReturn(true);
        when(roleRepository.findByUserId(5L)).thenReturn(List.of());
        when(jwtTokenService.createAccessToken(eq(5L), anyCollection())).thenReturn("access");
        when(jwtTokenService.createRefreshToken(eq(5L), anyCollection())).thenReturn("refresh");
        JwtPayload refreshPayload = new JwtPayload(5L, List.of(RoleName.ROLE_USER.name()), AuthTokenType.REFRESH, futureExpiry,
                "default-jti");
        when(jwtTokenService.parse("refresh")).thenReturn(refreshPayload);
        byte[] hashedJti = new byte[]{1, 2, 3};
        when(tokenHashService.hash(user.getId().toString())).thenReturn(hashedJti);
        when(encryptionContextFactory.createContext(argThat(bytes -> Arrays.equals(bytes, hashedJti)))).thenReturn(
                EncryptionContext.builder().id(12L).aadHash(hashedJti).build());
        when(authTokenRepository.save(any(AuthToken.class))).thenAnswer(invocation -> invocation.getArgument(0));

        SignInResult result = authService.signIn("empty@example.com", "pw", null);

        assertThat(result.accessToken()).isEqualTo("access");
        assertThat(result.refreshToken()).isEqualTo("refresh");

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Collection<RoleName>> rolesCaptor = ArgumentCaptor.forClass(Collection.class);
        verify(jwtTokenService).createAccessToken(eq(5L), rolesCaptor.capture());
        assertThat(rolesCaptor.getValue()).containsExactly(RoleName.ROLE_USER);
    }

    @Test
    void signIn_whenUserNotFound_throwsInvalidCredentials() {
        when(userRepository.findByEmail("missing@example.com")).thenReturn(Optional.empty());

        AuthException ex = assertThrows(AuthException.class,
                () -> authService.signIn("missing@example.com", "pw", null));

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.NOT_FOUND);
        verify(passwordEncoder, never()).matches(any(), any());
    }

    @Test
    void signIn_whenUserDeleted_throwsDeletedAccount() {
        User user = buildUser(7L, "deleted@example.com", "secret", OffsetDateTime.now().minusDays(1));
        when(userRepository.findByEmail("deleted@example.com")).thenReturn(Optional.of(user));

        AuthException ex = assertThrows(AuthException.class,
                () -> authService.signIn("deleted@example.com", "secret", null));

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.FORBIDDEN);
        verify(passwordEncoder, never()).matches(any(), any());
    }

    @Test
    void signIn_whenPasswordMismatch_throwsInvalidCredentials() {
        User user = buildUser(3L, "user@example.com", "encoded", null);
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong", "encoded")).thenReturn(false);

        AuthException ex = assertThrows(AuthException.class,
                () -> authService.signIn("user@example.com", "wrong", null));

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void signUp_createsUserWithNormalizedEmailAndDefaultRole() {
        SignUpCommand command = new SignUpCommand(" NewUser@Email.com ", "raw-pass", " Nick ", 10L);

        when(userRepository.findByEmail("newuser@email.com")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("raw-pass")).thenReturn("encoded");
        byte[] emailHash = new byte[]{9, 9};
        when(tokenHashService.hash("newuser@email.com")).thenReturn(emailHash);
        EncryptionContext userContext = EncryptionContext.builder().id(30L).aadHash(emailHash).build();
        when(encryptionContextFactory.createContext(argThat(bytes -> Arrays.equals(bytes, emailHash))))
                .thenReturn(userContext);
        EmailVerification verified = EmailVerification.builder()
                .id(10L)
                .email("newuser@email.com")
                .code("123456")
                .expiredAt(OffsetDateTime.now().plusMinutes(5))
                .verified(true)
                .encryptionContext(EncryptionContext.builder().id(1L).build())
                .build();
        when(emailVerificationService.requireVerified(10L, "newuser@email.com")).thenReturn(verified);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User pending = invocation.getArgument(0);
            return User.builder()
                    .id(100L)
                    .email(pending.getEmail())
                    .password(pending.getPassword())
                    .nickname(pending.getNickname())
                    .sns(pending.isSns())
                    .encryptionContext(pending.getEncryptionContext())
                    .build();
        });
        when(roleRepository.existsByUserIdAndRoleName(100L, RoleName.ROLE_USER)).thenReturn(false);
        when(roleRepository.save(any(Role.class))).thenAnswer(invocation -> invocation.getArgument(0));

        authService.signUp(command);

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User saved = userCaptor.getValue();
        assertThat(saved.getEmail()).isEqualTo("newuser@email.com");
        assertThat(saved.getPassword()).isEqualTo("encoded");
        assertThat(saved.getNickname()).isEqualTo("Nick");
        assertThat(saved.getEncryptionContext()).isEqualTo(userContext);

        ArgumentCaptor<Role> roleCaptor = ArgumentCaptor.forClass(Role.class);
        verify(roleRepository).save(roleCaptor.capture());
        assertThat(roleCaptor.getValue().getRoleName()).isEqualTo(RoleName.ROLE_USER);
        assertThat(roleCaptor.getValue().getUser().getId()).isEqualTo(100L);
    }

    @Test
    void signUp_whenEmailInUse_throwsDuplicateEmail() {
        User existing = buildUser(50L, "dup@example.com", "pass", null);
        when(userRepository.findByEmail("dup@example.com")).thenReturn(Optional.of(existing));

        SignUpCommand command = new SignUpCommand("dup@example.com", "pass", "Nick", 1L);
        AuthException ex = assertThrows(AuthException.class, () -> authService.signUp(command));

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.CONFLICT);
        verify(emailVerificationService, never()).requireVerified(anyLong(), any());
    }

    @Test
    void signUp_whenRoleAlreadyExists_skipsRoleCreation() {
        SignUpCommand command = new SignUpCommand("user@example.com", "pw", "Nick", 2L);

        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("pw")).thenReturn("encoded");
        byte[] emailHash = new byte[]{1};
        when(tokenHashService.hash("user@example.com")).thenReturn(emailHash);
        when(encryptionContextFactory.createContext(argThat(bytes -> Arrays.equals(bytes, emailHash)))).thenReturn(
                EncryptionContext.builder().id(4L).aadHash(emailHash).build());
        EmailVerification verified = EmailVerification.builder()
                .id(2L)
                .email("user@example.com")
                .code("654321")
                .expiredAt(OffsetDateTime.now().plusMinutes(5))
                .verified(true)
                .encryptionContext(EncryptionContext.builder().id(1L).build())
                .build();
        when(emailVerificationService.requireVerified(2L, "user@example.com")).thenReturn(verified);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> buildUser(77L,
                invocation.<User>getArgument(0).getEmail(),
                invocation.<User>getArgument(0).getPassword(),
                null));
        when(roleRepository.existsByUserIdAndRoleName(77L, RoleName.ROLE_USER)).thenReturn(true);

        authService.signUp(command);

        verify(roleRepository, never()).save(any(Role.class));
    }

    @Test
    void signUp_whenEmailMissing_throwsEmailRequired() {
        SignUpCommand command = new SignUpCommand(null, "pw", "Nick", 3L);

        AuthException ex = assertThrows(AuthException.class, () -> authService.signUp(command));

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
        verifyNoInteractions(userRepository, emailVerificationService);
    }

    @Test
    void reissue_withValidRefreshToken_revokesOldAndIssuesNew() {
        OffsetDateTime future = OffsetDateTime.now().plusHours(1);
        User user = buildUser(10L, "user@example.com", "encoded", null);
        JwtPayload refreshPayload = new JwtPayload(10L, List.of(RoleName.ROLE_USER.name()), AuthTokenType.REFRESH, future,
                "stored-jti");
        JwtPayload newPayload = new JwtPayload(10L, List.of(RoleName.ROLE_USER.name()), AuthTokenType.REFRESH,
                future.plusHours(4), "new-jti");

        byte[] userHash = new byte[]{3, 3};

        AuthToken storedToken = AuthToken.builder()
                .id(5L)
                .user(user)
                .type(AuthTokenType.REFRESH)
                .token("refresh-token")
                .expiredAt(future)
                .encryptionContext(EncryptionContext.builder().aadHash(userHash).build())
                .build();

        when(jwtTokenService.parse("refresh-token")).thenReturn(refreshPayload);
        when(tokenHashService.hash(user.getId().toString())).thenReturn(userHash);
        when(userRepository.findById(10L)).thenReturn(Optional.of(user));
        when(authTokenRepository.findByUserIdAndToken(10L, "refresh-token")).thenReturn(Optional.of(storedToken));
        when(authTokenRepository.findByUserIdAndEncryptionContextAadHash(10L, userHash))
                .thenReturn(Optional.of(storedToken));
        when(roleRepository.findByUserId(10L)).thenReturn(List.of(Role.builder().roleName(RoleName.ROLE_USER).build()));
        when(authTokenRepository.save(any(AuthToken.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(jwtTokenService.createAccessToken(eq(10L), anyCollection())).thenReturn("new-access");
        when(jwtTokenService.createRefreshToken(eq(10L), anyCollection())).thenReturn("new-refresh");
        when(jwtTokenService.parse("new-refresh")).thenReturn(newPayload);
        EncryptionContext newContext = EncryptionContext.builder().id(80L).aadHash(userHash).build();
        when(encryptionContextFactory.createContext(argThat(bytes -> Arrays.equals(bytes, userHash))))
                .thenReturn(newContext);

        TokenPair pair = authService.reissue(10L, "refresh-token", new ClientMetadata("agent", "ip"));

        assertThat(pair.accessToken()).isEqualTo("new-access");
        assertThat(pair.refreshToken()).isEqualTo("new-refresh");
        assertThat(storedToken.isRevoked()).isTrue();

        ArgumentCaptor<AuthToken> tokenCaptor = ArgumentCaptor.forClass(AuthToken.class);
        verify(authTokenRepository, times(2)).save(tokenCaptor.capture());
        List<AuthToken> savedTokens = tokenCaptor.getAllValues();
        assertThat(savedTokens.get(0)).isSameAs(storedToken);
        assertThat(savedTokens.get(0).isRevoked()).isTrue();
        assertThat(savedTokens.get(1).getType()).isEqualTo(AuthTokenType.REFRESH);
        assertThat(savedTokens.get(1).getEncryptionContext()).isEqualTo(newContext);
        assertThat(savedTokens.get(1).getUser()).isEqualTo(user);
    }

    @Test
    void reissue_whenUserIdDiffers_throwsRefreshTokenUserMismatch() {
        JwtPayload payload = new JwtPayload(5L, List.of(RoleName.ROLE_USER.name()), AuthTokenType.REFRESH, OffsetDateTime.now().plusHours(1),
                "jti");
        User user = buildUser(6L, "user@example.com", "pw", null);
        byte[] hash = new byte[]{6};
        AuthToken stored = AuthToken.builder()
                .user(user)
                .token("refresh-token")
                .type(AuthTokenType.REFRESH)
                .expiredAt(OffsetDateTime.now().plusHours(1))
                .encryptionContext(EncryptionContext.builder().aadHash(hash).build())
                .build();

        when(userRepository.findById(6L)).thenReturn(Optional.of(user));
        when(authTokenRepository.findByUserIdAndToken(6L, "refresh-token")).thenReturn(Optional.of(stored));
        when(tokenHashService.hash("6")).thenReturn(hash);
        when(jwtTokenService.parse("refresh-token")).thenReturn(payload);

        AuthException ex = assertThrows(AuthException.class, () -> authService.reissue(6L, "refresh-token", null));
        assertThat(ex.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void reissue_whenTokenTypeInvalid_throwsInvalidTokenType() {
        JwtPayload payload = new JwtPayload(1L, List.of("ROLE_USER"), AuthTokenType.ACCESS, OffsetDateTime.now().plusHours(1),
                "jti");
        User user = buildUser(1L, "user@example.com", "enc", null);
        AuthToken storedToken = mock(AuthToken.class);

        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(jwtTokenService.parse("refresh-token")).thenReturn(payload);
        when(authTokenRepository.findByUserIdAndToken(1L, "refresh-token")).thenReturn(Optional.of(storedToken));
        when(storedToken.getDecodeToken(anyString(), any(), any())).thenReturn("refresh-token");

        AuthException ex = assertThrows(AuthException.class, () -> authService.reissue(1L, "refresh-token", null));
        assertThat(ex.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void reissue_whenUserNotFound_throwsUserNotFound() {
        JwtPayload payload = new JwtPayload(2L, List.of("ROLE_USER"), AuthTokenType.REFRESH, OffsetDateTime.now().plusHours(1),
                "jti");
        // 실제 호출은 되지 않으니 테스트 코드라 가정하여 lenient() 처리
        lenient().when(jwtTokenService.parse("refresh-token")).thenReturn(payload);
        lenient().when(userRepository.findById(2L)).thenReturn(Optional.empty());

        AuthException ex = assertThrows(AuthException.class, () -> authService.reissue(2L, "refresh-token", null));
        assertThat(ex.getStatus()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void reissue_whenUserDeleted_throwsDeletedAccount() {
        User deleted = buildUser(2L, "deleted@example.com", "enc", OffsetDateTime.now().minusDays(1));
        when(userRepository.findById(2L)).thenReturn(Optional.of(deleted));

        AuthException ex = assertThrows(AuthException.class, () -> authService.reissue(2L, "refresh-token", null));
        assertThat(ex.getStatus()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void reissue_whenRefreshTokenMissing_throwsRefreshTokenMissing() {
        User user = buildUser(2L, "user@example.com", "enc", null);
        when(userRepository.findById(2L)).thenReturn(Optional.of(user));
        when(authTokenRepository.findByUserIdAndToken(2L, "refresh-token")).thenReturn(Optional.empty());

        AuthException ex = assertThrows(AuthException.class, () -> authService.reissue(2L, "refresh-token", null));
        assertThat(ex.getStatus()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void reissue_whenStoredTokenRevoked_throwsRefreshTokenInvalid() {
        OffsetDateTime future = OffsetDateTime.now().plusHours(1);
        JwtPayload payload = new JwtPayload(3L, List.of("ROLE_USER"), AuthTokenType.REFRESH, future, "jti");
        when(jwtTokenService.parse("refresh-token")).thenReturn(payload);
        User user = buildUser(3L, "user@example.com", "enc", null);
        when(userRepository.findById(3L)).thenReturn(Optional.of(user));
        byte[] hash = new byte[]{3};
        when(tokenHashService.hash(user.getId().toString())).thenReturn(hash);
        AuthToken stored = AuthToken.builder()
                .user(user)
                .token("refresh-token")
                .type(AuthTokenType.REFRESH)
                .expiredAt(future)
                .revokedAt(OffsetDateTime.now().minusMinutes(1))
                .encryptionContext(EncryptionContext.builder().aadHash(hash).build())
                .build();
        when(authTokenRepository.findByUserIdAndToken(3L, "refresh-token")).thenReturn(Optional.of(stored));
        when(authTokenRepository.findByUserIdAndEncryptionContextAadHash(3L, hash)).thenReturn(Optional.of(stored));

        AuthException ex = assertThrows(AuthException.class, () -> authService.reissue(3L, "refresh-token", null));
        assertThat(ex.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void reissue_whenStoredTokenExpired_throwsRefreshTokenInvalid() {
        OffsetDateTime past = OffsetDateTime.now().minusMinutes(5);
        JwtPayload payload = new JwtPayload(4L, List.of("ROLE_USER"), AuthTokenType.REFRESH, OffsetDateTime.now().plusHours(1),
                "jti");
        when(jwtTokenService.parse("refresh-token")).thenReturn(payload);
        User user = buildUser(4L, "user@example.com", "enc", null);
        when(userRepository.findById(4L)).thenReturn(Optional.of(user));
        byte[] hash = new byte[]{4};
        when(tokenHashService.hash(user.getId().toString())).thenReturn(hash);
        AuthToken stored = AuthToken.builder()
                .user(user)
                .token("refresh-token")
                .type(AuthTokenType.REFRESH)
                .expiredAt(past)
                .encryptionContext(EncryptionContext.builder().aadHash(hash).build())
                .build();
        when(authTokenRepository.findByUserIdAndEncryptionContextAadHash(4L, hash)).thenReturn(Optional.of(stored));
        when(authTokenRepository.findByUserIdAndToken(4L, "refresh-token")).thenReturn(Optional.of(stored));

        AuthException ex = assertThrows(AuthException.class, () -> authService.reissue(4L, "refresh-token", null));
        assertThat(ex.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void reissue_whenTokenParsingFails_wrapsException() {
        JwtProcessingException jwtException = mock(JwtProcessingException.class);
        User user = buildUser(1L, "user@example.com", "enc", null);
        byte[] hash = new byte[]{1};
        AuthToken stored = AuthToken.builder()
                .user(user)
                .token("bad-token")
                .type(AuthTokenType.REFRESH)
                .expiredAt(OffsetDateTime.now().plusHours(1))
                .encryptionContext(EncryptionContext.builder().aadHash(hash).build())
                .build();

        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(authTokenRepository.findByUserIdAndToken(1L, "bad-token")).thenReturn(Optional.of(stored));
        when(tokenHashService.hash("1")).thenReturn(hash);
        when(jwtTokenService.parse("bad-token")).thenThrow(jwtException);

        AuthException ex = assertThrows(AuthException.class, () -> authService.reissue(1L, "bad-token", null));
        assertThat(ex.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    private User buildUser(Long id, String email, String password, OffsetDateTime deletedAt) {
        return User.builder()
                .id(id)
                .email(email)
                .password(password)
                .nickname("Tester")
                .sns(false)
                .encryptionContext(EncryptionContext.builder().id(1L).build())
                .deletedAt(deletedAt)
                .build();
    }
}
