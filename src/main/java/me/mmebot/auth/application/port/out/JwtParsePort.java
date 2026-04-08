package me.mmebot.auth.application.port.out;

import me.mmebot.auth.jwt.JwtPayload;

public interface JwtParsePort {
    JwtPayload parse(String token);
}
