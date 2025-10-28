package me.mmebot.auth.service;

import jakarta.transaction.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.auth.api.dto.GoogleTokenResponse;
import me.mmebot.auth.domain.ProviderToken;
import me.mmebot.auth.domain.token.TokenCipher;
import me.mmebot.auth.domain.token.TokenCipherException;
import me.mmebot.auth.domain.token.TokenCipherSpec;
import me.mmebot.auth.exception.GoogleOAuthException;
import me.mmebot.auth.exception.ProviderTokenException;
import me.mmebot.auth.repository.ProviderTokenRepository;
import me.mmebot.common.mail.GoogleProperties;
import me.mmebot.common.mail.ProviderConstant;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class ProviderTokenService {

    private static final String PROVIDER_GOOGLE = ProviderConstant.GOOGLE;

    private final ProviderTokenRepository providerTokenRepository;
    private final TokenCipher tokenCipher;
    private final TokenHashService tokenHashService;
    private final GoogleProperties googleProperties;
    private final RestTemplate restTemplate = new RestTemplate();

    public void refreshAccessToken() {
        ProviderToken providerToken = providerTokenRepository.findByProvider(PROVIDER_GOOGLE)
                .orElseThrow(GoogleOAuthException::requestFailed);

        String clientId = resolveClientId();
        try {
            String authorizationCode = providerToken.getDecodeAuthorizationCode(tokenCipher, tokenHashService);

            Map<String, String> params = new HashMap<>();
            params.put("client_id", clientId);
            params.put("client_secret", googleProperties.clientSecret());
            params.put("code", authorizationCode);
            params.put("redirect_uri", googleProperties.redirectUri());
            params.put("grant_type", "authorization_code");

            requestToken(params);
        } catch (TokenCipherException ex) {
            log.error("Failed to decrypt authorization code for provider {}", PROVIDER_GOOGLE, ex);
            throw GoogleOAuthException.requestFailed();
        }
    }

    private void requestToken(Map<String, String> params) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.setAll(params);

            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(form, headers);

            ResponseEntity<GoogleTokenResponse> response = restTemplate.postForEntity(
                    googleProperties.tokenUrl(), entity, GoogleTokenResponse.class
            );

            if (response.getStatusCode().is2xxSuccessful()) {
                GoogleTokenResponse tokenResponse = response.getBody();
                if (tokenResponse == null) {
                    log.error("request token failed: empty response body");
                    throw GoogleOAuthException.requestFailed();
                }
                storeProviderTokens(tokenResponse);
            } else {
                log.error("request token failed, status code: {}", response.getStatusCode());
                throw GoogleOAuthException.failedGetRefreshToken(response.getStatusCode());
            }
        } catch (Exception ex) {
            log.error("request token failed: {}", ex.getMessage(), ex);
            throw GoogleOAuthException.requestFailed();
        }
        log.info("request token finished");
    }

    private void storeProviderTokens(GoogleTokenResponse tokenResponse) {

        String clientId = resolveClientId();
        ProviderToken providerToken = providerTokenRepository.findByProviderAndClientId(PROVIDER_GOOGLE, clientId)
                .orElseGet(() -> ProviderToken.builder()
                        .provider(PROVIDER_GOOGLE)
                        .clientId(clientId)
                        .build());

        OffsetDateTime now = OffsetDateTime.now();
        OffsetDateTime expiresAt = tokenResponse.expiresIn() > 0
                ? now.plusSeconds(tokenResponse.expiresIn())
                : null;

        try {
            if (tokenResponse.accessToken() != null && !tokenResponse.accessToken().isBlank()) {
                providerToken.storeAccessToken(
                        tokenResponse.accessToken(),
                        expiresAt,
                        tokenResponse.tokenType(),
                        tokenResponse.scope(),
                        now,
                        tokenHashService,
                        tokenCipher
                );
            }

            String refreshToken = tokenResponse.refreshToken();
            if (refreshToken != null && !refreshToken.isBlank()) {
                providerToken.storeRefreshToken(refreshToken, tokenCipher, tokenHashService);
            }

            providerTokenRepository.save(providerToken);
            log.info("Stored provider tokens for provider {} and client {}", PROVIDER_GOOGLE, clientId);
        } catch (TokenCipherException ex) {
            log.error("Failed to encrypt provider tokens for client {}", clientId, ex);
            throw GoogleOAuthException.requestFailed();
        }
    }

    public void storeGoogleAuthorizationCode(String authorizationCode) {
        String normalizedCode = normalizeCode(authorizationCode);
        String clientId = resolveClientId();
        try {

            ProviderToken token = providerTokenRepository.findByProviderAndClientId(PROVIDER_GOOGLE, clientId)
                    .orElseGet(() -> ProviderToken.builder()
                            .provider(PROVIDER_GOOGLE)
                            .clientId(clientId)
                            .build());
            token.storeAuthorizationCode(normalizedCode, tokenHashService, tokenCipher);

            providerTokenRepository.save(token);
            log.info("Stored encrypted authorization code for provider {} and client {}", PROVIDER_GOOGLE, clientId);
        } catch (TokenCipherException ex) {
            log.error("Failed to encrypt authorization code for provider {}", PROVIDER_GOOGLE, ex);
            throw GoogleOAuthException.requestFailed();
        }
    }

    private TokenCipherSpec googleAuthorizationSpec(String clientId) {
        byte[] aad = clientId.getBytes(StandardCharsets.UTF_8);
        byte[] aadHash = tokenHashService.hash(clientId);
        return TokenCipherSpec.of(aad, aadHash);
    }

    private String safeDecrypt(Supplier<String> supplier) {
        try {
            return supplier.get();
        } catch (TokenCipherException ex) {
            log.error("Failed to decrypt provider token for {}", PROVIDER_GOOGLE, ex);
            throw GoogleOAuthException.requestFailed();
        }
    }

    private String normalizeCode(String authorizationCode) {
        if (authorizationCode == null || authorizationCode.trim().isEmpty()) {
            log.error("Provided authorization code is null or empty");
            throw ProviderTokenException.authorizationCodeMissing();
        }
        return authorizationCode.trim();
    }

    private String resolveClientId() {
        String clientId = googleProperties.clientId();
        if (clientId == null || clientId.trim().isEmpty()) {
            log.error("Provided client id is null or empty");
            throw ProviderTokenException.clientConfigurationMissing();
        }
        return clientId.trim();
    }

    public String getRefreshToken(String provider) {
        ProviderToken providerToken = providerTokenRepository.findByProviderAndClientId(provider, resolveClientId())
                .orElseThrow(() -> GoogleOAuthException.failedGetRefreshToken(HttpStatus.UNAUTHORIZED));
        return providerToken.getDecodeRefreshToken(tokenCipher, tokenHashService);
    }
}
