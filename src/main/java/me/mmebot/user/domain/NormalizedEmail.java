package me.mmebot.user.domain;

import java.util.Locale;

public record NormalizedEmail(String value) {

    public NormalizedEmail {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Email must not be blank");
        }
    }

    public static NormalizedEmail from(String email) {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("Email must not be blank");
        }
        return new NormalizedEmail(email.trim().toLowerCase(Locale.ROOT));
    }

    @Override
    public String toString() {
        return value;
    }
}
