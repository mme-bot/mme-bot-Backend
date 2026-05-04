package me.mmebot.auth.domain.token;

import java.util.Objects;
import me.mmebot.core.domain.EncryptionContextEntity;

/**
 * Value object holding an encrypted token and its persistence context.
 */
public record EncryptedToken(String payload, EncryptionContextEntity context) {

    public EncryptedToken {
        Objects.requireNonNull(payload, "payload must not be null");
        Objects.requireNonNull(context, "context must not be null");
    }
}
