package me.mmebot.auth.service;

import jakarta.transaction.Transactional;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.Map;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.auth.api.dto.GoogleTokenResponse;
import me.mmebot.auth.domain.ProviderToken;
import me.mmebot.auth.exception.GoogleOAuthException;
import me.mmebot.auth.exception.ProviderTokenException;
import me.mmebot.auth.repository.ProviderTokenRepository;
import me.mmebot.common.mail.GoogleProperties;
import me.mmebot.core.domain.EncryptionContext;
import me.mmebot.core.service.AesGcmEncryptor;
import me.mmebot.core.service.AesGcmEncryptor.EncryptionResult;
import me.mmebot.core.service.EncryptionContextFactory;
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

    private static final String PROVIDER_GOOGLE = "GOOGLE";

    private final ProviderTokenRepository providerTokenRepository;
    private final EncryptionContextFactory encryptionContextFactory;
    private final AesGcmEncryptor encryptor;
    private final TokenHashService tokenHashService;
    private final GoogleProperties googleProperties;
    private final RestTemplate restTemplate = new RestTemplate();

    public void refreshAccessToken() {
        ProviderToken providerToken = providerTokenRepository.findByProvider(PROVIDER_GOOGLE)
                .orElseThrow(GoogleOAuthException::requestFailed);

        Map<String, String> params = new HashMap<>();

        String decryptCode = encryptor.decrypt(
                providerToken.getAuthorizationCode(),
                providerToken.getEncryptionContext(),
                googleProperties.clientId().getBytes(StandardCharsets.UTF_8)
        );

        params.put("client_id", googleProperties.clientId());
        params.put("client_secret", googleProperties.clientSecret());
        params.put("code", decryptCode);
        params.put("redirect_uri", googleProperties.redirectUri());
        params.put("grant_type", "authorization_code");

        requestToken(params);
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
            log.info("request token finished");
        } catch (Exception ex) {
            log.error("request token failed: {}", ex.getMessage(), ex);
            throw GoogleOAuthException.requestFailed();
        }
    }

    private void storeProviderTokens(GoogleTokenResponse tokenResponse) {
        String clientId = resolveClientId();
        ProviderToken providerToken = providerTokenRepository.findByProviderAndClientId(PROVIDER_GOOGLE, clientId)
                .orElseGet(() -> ProviderToken.builder()
                        .provider(PROVIDER_GOOGLE)
                        .clientId(clientId)
                        .encryptionContext(encryptionContextFactory.createContext())
                        .build());

        OffsetDateTime now = OffsetDateTime.now();
        OffsetDateTime expiresAt = tokenResponse.expiresIn() > 0
                ? now.plusSeconds(tokenResponse.expiresIn())
                : null;

        providerToken.applyTokenResponse(
                tokenResponse.accessToken(),
                expiresAt,
                tokenResponse.tokenType(),
                tokenResponse.scope(),
                now
        );

        String refreshToken = tokenResponse.refreshToken();
        if (refreshToken != null && !refreshToken.isBlank()) {
            EncryptionContext context = encryptionContextFactory.createContext();
            EncryptionResult encryptedRefreshToken = encryptor.encrypt(refreshToken, context, null);
            context.updateTag(encryptedRefreshToken.tag());
            providerToken.applyRefreshToken(encryptedRefreshToken.payload(), context);
        }

        providerTokenRepository.save(providerToken);
        log.info("Stored provider tokens for provider {} and client {}", PROVIDER_GOOGLE, clientId);
    }

    public void storeGoogleAuthorizationCode(String authorizationCode) {
        String normalizedCode = normalizeCode(authorizationCode);
        String clientId = resolveClientId();
        String normalizedState = clientId;
        byte[] aad = normalizedState.getBytes(StandardCharsets.UTF_8);
        byte[] aadHash = tokenHashService.hash(normalizedState);

        EncryptionContext context = encryptionContextFactory.createContext(aadHash);
        EncryptionResult encrypted = encryptor.encrypt(normalizedCode, context, aad);
        context.updateTag(encrypted.tag());

        ProviderToken token = providerTokenRepository.findByProviderAndClientId(PROVIDER_GOOGLE, clientId)
                .orElseGet(() -> ProviderToken.builder()
                        .provider(PROVIDER_GOOGLE)
                        .clientId(clientId)
                        .encryptionContext(context)
                        .build());
        token.applyAuthorizationCode(encrypted.payload(), context);

        providerTokenRepository.save(token);
        log.info("Stored encrypted authorization code for provider {} and client {}", PROVIDER_GOOGLE, clientId);
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

}
