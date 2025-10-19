package me.mmebot.auth.exception;

import me.mmebot.common.exception.ApiException;
import org.springframework.http.HttpStatus;

public class ProviderTokenException extends ApiException {

    private ProviderTokenException(HttpStatus status, String message, String errorCode) {
        super(status, message, errorCode);
    }

    public static ProviderTokenException authorizationCodeMissing() {
        return new ProviderTokenException(HttpStatus.BAD_REQUEST, "Authorization code is required", "provider_token.authorization_code_missing");
    }

    public static ProviderTokenException clientConfigurationMissing() {
        return new ProviderTokenException(HttpStatus.INTERNAL_SERVER_ERROR, "OAuth client configuration is missing", "provider_token.client_configuration_missing");
    }
}
