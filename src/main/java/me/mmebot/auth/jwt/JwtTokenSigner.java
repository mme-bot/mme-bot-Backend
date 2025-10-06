package me.mmebot.auth.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import me.mmebot.common.config.JwtProperties;
import org.springframework.stereotype.Component;

@Component
public class JwtTokenSigner {

    private final JwtKeyProvider keyProvider;
    private final JwtProperties properties;

    public JwtTokenSigner(JwtKeyProvider keyProvider, JwtProperties properties) {
        this.keyProvider = keyProvider;
        this.properties = properties;
    }

    public SignedJWT sign(JWTClaimsSet claimsSet) {
        try {
            SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256)
                    .type(JOSEObjectType.JWT)
                    .keyID(properties.keyId())
                    .build(), claimsSet);
            signedJWT.sign(new MACSigner(keyProvider.signingKey()));
            return signedJWT;
        } catch (JOSEException ex) {
            throw new JwtProcessingException("Failed to sign JWT", ex);
        }
    }
}
