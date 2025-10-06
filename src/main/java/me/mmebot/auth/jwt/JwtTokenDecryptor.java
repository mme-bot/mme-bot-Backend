package me.mmebot.auth.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import org.springframework.stereotype.Component;

@Component
public class JwtTokenDecryptor {

    private final JwtKeyProvider keyProvider;

    public JwtTokenDecryptor(JwtKeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }

    public SignedJWT decrypt(String token) {
        try {
            JWEObject jweObject = JWEObject.parse(token);
            jweObject.decrypt(new DirectDecrypter(keyProvider.encryptionKey()));
            return SignedJWT.parse(jweObject.getPayload().toString());
        } catch (ParseException | JOSEException ex) {
            throw new JwtProcessingException("Failed to decrypt JWT", ex);
        }
    }
}
