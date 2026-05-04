package me.mmebot.auth.adapter.out.crypto;

import lombok.RequiredArgsConstructor;
import me.mmebot.auth.application.port.out.crypto.TokenHashPort;
import me.mmebot.auth.service.TokenHashService;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class TokenHashAdapter implements TokenHashPort {

    private final TokenHashService tokenHashService;

    @Override
    public byte[] hash(String value) {
        return tokenHashService.hash(value);
    }
}
