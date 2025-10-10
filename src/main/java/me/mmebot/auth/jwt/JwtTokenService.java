package me.mmebot.auth.jwt;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.auth.domain.RoleName;
import me.mmebot.common.config.JwtProperties;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class JwtTokenService {

    private static final String CLAIM_USER_ID = "user_id";
    private static final String CLAIM_ROLES = "roles";
    private static final String CLAIM_TOKEN_TYPE = "token_type";

    private final JwtTokenSigner signer;
    private final JwtTokenVerifier verifier;
    private final JwtTokenEncryptor encryptor;
    private final JwtTokenDecryptor decryptor;
    private final JwtProperties properties;

    public JwtTokenService(JwtTokenSigner signer,
                           JwtTokenVerifier verifier,
                           JwtTokenEncryptor encryptor,
                           JwtTokenDecryptor decryptor,
                           JwtProperties properties) {
        this.signer = signer;
        this.verifier = verifier;
        this.encryptor = encryptor;
        this.decryptor = decryptor;
        this.properties = properties;
    }

    public String createAccessToken(Long userId, Collection<RoleName> roleNames) {
        String token = createToken(userId, roleNames.stream().map(RoleName::name).toList(),
                properties.accessTokenExpiry(), "access");
        log.debug("Access token issued for user {}", userId);
        return token;
    }

    public String createRefreshToken(Long userId, Collection<RoleName> roleNames) {
        String token = createToken(userId, roleNames.stream().map(RoleName::name).toList(),
                properties.refreshTokenExpiry(), "refresh");
        log.debug("Refresh token issued for user {}", userId);
        return token;
    }

    public JwtPayload parse(String token) {
        SignedJWT signedJWT;
        try {
            signedJWT = decryptor.decrypt(token);
        } catch (JwtProcessingException ex) {
            log.error("JWT parsing failed during decryption", ex);
            throw ex;
        }
        try {
            verifier.verify(signedJWT);
        } catch (JwtProcessingException ex) {
            log.error("JWT parsing failed during signature verification", ex);
            throw ex;
        }
        try {
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            validate(claims);

            List<String> roles = claims.getStringListClaim(CLAIM_ROLES);
            Long userId = claims.getLongClaim(CLAIM_USER_ID);
            String tokenType = claims.getStringClaim(CLAIM_TOKEN_TYPE);
            OffsetDateTime expiresAt = claims.getExpirationTime() == null
                    ? null
                    : OffsetDateTime.ofInstant(claims.getExpirationTime().toInstant(), ZoneOffset.UTC);

            log.debug("Parsed {} token for user {}", tokenType, userId);
            return new JwtPayload(userId, roles, tokenType, expiresAt, claims.getJWTID());
        } catch (ParseException ex) {
            log.error("Failed to parse JWT claims", ex);
            throw new JwtProcessingException("Failed to read JWT claims", ex);
        }
    }

    private String createToken(Long userId,
                               Collection<String> roles,
                               Duration lifetime,
                               String tokenType) {
        if (lifetime == null) {
            log.error("Unable to create {} token: lifetime not configured", tokenType);
            throw new IllegalStateException("JWT lifetime must be configured");
        }
        Instant now = Instant.now();
        Instant expiresAt = now.plus(lifetime);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(properties.issuer())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(expiresAt))
                .notBeforeTime(Date.from(now))
                .subject(String.valueOf(userId))
                .claim(CLAIM_USER_ID, userId)
                .claim(CLAIM_ROLES, roles)
                .claim(CLAIM_TOKEN_TYPE, tokenType)
                .jwtID(UUID.randomUUID().toString())
                .build();
        SignedJWT signedJWT;
        try {
            signedJWT = signer.sign(claimsSet);
        } catch (JwtProcessingException ex) {
            log.error("Signing {} token failed for user {}", tokenType, userId, ex);
            throw ex;
        }
        String encrypted;
        try {
            encrypted = encryptor.encrypt(signedJWT);
        } catch (JwtProcessingException ex) {
            log.error("Encrypting {} token failed for user {}", tokenType, userId, ex);
            throw ex;
        }
        log.debug("Successfully created {} token for user {} expiring at {}", tokenType, userId,
                OffsetDateTime.ofInstant(expiresAt, ZoneOffset.UTC));
        return encrypted;
    }

    private void validate(JWTClaimsSet claims) {
        if (!Objects.equals(properties.issuer(), claims.getIssuer())) {
            log.warn("JWT validation failed: unexpected issuer {}", claims.getIssuer());
            throw new JwtProcessingException("Invalid JWT issuer");
        }
        Date expirationTime = claims.getExpirationTime();
        if (expirationTime == null) {
            log.warn("JWT validation failed: missing expiration claim");
            throw new JwtProcessingException("JWT is missing expiration claim");
        }
        if (Instant.now().isAfter(expirationTime.toInstant())) {
            log.warn("JWT validation failed: token expired at {}", expirationTime);
            throw new JwtProcessingException("JWT token expired");
        }
        if (claims.getClaim(CLAIM_USER_ID) == null) {
            log.warn("JWT validation failed: missing user identifier");
            throw new JwtProcessingException("JWT payload missing user identifier");
        }
        if (claims.getClaim(CLAIM_ROLES) == null) {
            log.warn("JWT validation failed: missing roles claim");
            throw new JwtProcessingException("JWT payload missing roles");
        }
    }
}
