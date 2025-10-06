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
import me.mmebot.auth.domain.RoleName;
import me.mmebot.common.config.JwtProperties;
import org.springframework.stereotype.Component;

@Component
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
        return createToken(userId, roleNames.stream().map(RoleName::name).toList(),
                properties.accessTokenExpiry(), "access");
    }

    public String createRefreshToken(Long userId, Collection<RoleName> roleNames) {
        return createToken(userId, roleNames.stream().map(RoleName::name).toList(),
                properties.refreshTokenExpiry(), "refresh");
    }

    public JwtPayload parse(String token) {
        SignedJWT signedJWT = decryptor.decrypt(token);
        verifier.verify(signedJWT);
        try {
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            validate(claims);

            List<String> roles = claims.getStringListClaim(CLAIM_ROLES);
            Long userId = claims.getLongClaim(CLAIM_USER_ID);
            String tokenType = claims.getStringClaim(CLAIM_TOKEN_TYPE);
            OffsetDateTime expiresAt = claims.getExpirationTime() == null
                    ? null
                    : OffsetDateTime.ofInstant(claims.getExpirationTime().toInstant(), ZoneOffset.UTC);

            return new JwtPayload(userId, roles, tokenType, expiresAt, claims.getJWTID());
        } catch (ParseException ex) {
            throw new JwtProcessingException("Failed to read JWT claims", ex);
        }
    }

    private String createToken(Long userId,
                               Collection<String> roles,
                               Duration lifetime,
                               String tokenType) {
        if (lifetime == null) {
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
        SignedJWT signedJWT = signer.sign(claimsSet);
        return encryptor.encrypt(signedJWT);
    }

    private void validate(JWTClaimsSet claims) {
        if (!Objects.equals(properties.issuer(), claims.getIssuer())) {
            throw new JwtProcessingException("Invalid JWT issuer");
        }
        Date expirationTime = claims.getExpirationTime();
        if (expirationTime == null) {
            throw new JwtProcessingException("JWT is missing expiration claim");
        }
        if (Instant.now().isAfter(expirationTime.toInstant())) {
            throw new JwtProcessingException("JWT token expired");
        }
        if (claims.getClaim(CLAIM_USER_ID) == null) {
            throw new JwtProcessingException("JWT payload missing user identifier");
        }
        if (claims.getClaim(CLAIM_ROLES) == null) {
            throw new JwtProcessingException("JWT payload missing roles");
        }
    }
}
