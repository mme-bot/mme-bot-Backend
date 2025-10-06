package me.mmebot.auth.jwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Component;

@Component
public class JwtTokenEncryptor {

    private final JwtKeyProvider keyProvider;

    public JwtTokenEncryptor(JwtKeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }

    public String encrypt(SignedJWT signedJWT) {
        try {
            JWEObject jweObject = new JWEObject(
                    new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM)
                            .contentType(JOSEObjectType.JWT.getType())
                            .build(),
                    new Payload(signedJWT.serialize())
            );
            jweObject.encrypt(new DirectEncrypter(keyProvider.encryptionKey()));
            return jweObject.serialize();
        } catch (JOSEException ex) {
            throw new JwtProcessingException("Failed to encrypt JWT", ex);
        }
    }
}
