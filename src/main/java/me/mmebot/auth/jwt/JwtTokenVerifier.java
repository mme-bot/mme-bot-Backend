package me.mmebot.auth.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Component;

@Component
public class JwtTokenVerifier {

    private final JwtKeyProvider keyProvider;

    public JwtTokenVerifier(JwtKeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }

    public void verify(SignedJWT signedJWT) {
        try {
            if (!signedJWT.verify(new MACVerifier(keyProvider.signingKey()))) {
                throw new JwtProcessingException("Invalid JWT signature");
            }
        } catch (JOSEException ex) {
            throw new JwtProcessingException("Failed to verify JWT", ex);
        }
    }
}
