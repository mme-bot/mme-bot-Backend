package me.mmebot.auth.adapter.in.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import me.mmebot.auth.adapter.in.web.dto.CheckEmailVerificationRequest;
import me.mmebot.auth.adapter.in.web.dto.LogoutRequest;
import me.mmebot.auth.adapter.in.web.dto.SendEmailVerificationRequest;
import me.mmebot.auth.adapter.in.web.dto.SendEmailVerificationResponse;
import me.mmebot.auth.adapter.in.web.dto.SignInRequest;
import me.mmebot.auth.adapter.in.web.dto.SignInResponse;
import me.mmebot.auth.adapter.in.web.dto.SignUpRequest;
import me.mmebot.auth.adapter.in.web.dto.TokenReissueRequest;
import me.mmebot.auth.adapter.in.web.dto.TokenReissueResponse;
import me.mmebot.auth.application.command.ClientMetadata;
import me.mmebot.auth.application.command.LogoutCommand;
import me.mmebot.auth.application.command.ReissueTokenCommand;
import me.mmebot.auth.application.command.SignInCommand;
import me.mmebot.auth.application.command.SignUpCommand;
import me.mmebot.auth.application.port.in.LogoutUseCase;
import me.mmebot.auth.application.port.in.ReissueTokenUseCase;
import me.mmebot.auth.application.port.in.SignInUseCase;
import me.mmebot.auth.application.port.in.SignUpUseCase;
import me.mmebot.auth.application.result.SignInResult;
import me.mmebot.auth.application.result.TokenPairResult;
import me.mmebot.auth.service.EmailVerificationResult;
import me.mmebot.common.config.JwtProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("${api.base-path}/auth")
@RequiredArgsConstructor
public class AuthController {

    private static final String ACCESS_TOKEN_COOKIE = "access_token";

    private final SignInUseCase signInUseCase;
    private final SignUpUseCase signUpUseCase;
    private final LogoutUseCase logoutUseCase;
    private final ReissueTokenUseCase reissueTokenUseCase;
//    private final EmailVerificationService emailVerificationService;
    private final JwtProperties jwtProperties;

    @PostMapping("/login")
    public SignInResponse signIn(@Valid @RequestBody SignInRequest request,
                                 HttpServletRequest httpRequest,
                                 HttpServletResponse httpResponse) {
        SignInResult result = signInUseCase.signIn(new SignInCommand(
                request.email(),
                request.passwd(),
                resolveClientMetadata(httpRequest)
        ));
        writeAccessTokenCookie(httpResponse, result.accessToken());
        return new SignInResponse(result.userId(), result.botId(), result.nickname(),
                result.accessToken(), result.refreshToken());
    }

    @PostMapping("/sign-up")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void signUp(@Valid @RequestBody SignUpRequest request) {
        signUpUseCase.signUp(new SignUpCommand(
                request.email(),
                request.passwd(),
                request.nickname()
        ));
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@AuthenticationPrincipal Long userId,
                       @Valid @RequestBody LogoutRequest request,
                       HttpServletResponse httpResponse) {
        logoutUseCase.logout(new LogoutCommand(userId, request.refreshToken()));
        expireAccessTokenCookie(httpResponse);
    }

    @PostMapping("/token-reissue")
    public TokenReissueResponse reissueToken(@Valid @RequestBody TokenReissueRequest request,
                                             HttpServletRequest httpRequest,
                                             HttpServletResponse httpResponse) {
        TokenPairResult tokens = reissueTokenUseCase.reissue(new ReissueTokenCommand(
                request.userId(),
                request.refreshToken(),
                resolveClientMetadata(httpRequest)
        ));
        writeAccessTokenCookie(httpResponse, tokens.accessToken());
        return new TokenReissueResponse(tokens.accessToken(), tokens.refreshToken());
    }

//    @PostMapping("/email-verification/send")
//    public SendEmailVerificationResponse sendEmailVerification(@Valid @RequestBody SendEmailVerificationRequest request) {
//        EmailVerificationResult result = emailVerificationService.send(request.email());
//        return new SendEmailVerificationResponse(result.emailVerificationId(), result.code());
//    }
//
//    @PostMapping("/email-verification/check")
//    @ResponseStatus(HttpStatus.NO_CONTENT)
//    public void checkEmailVerification(@Valid @RequestBody CheckEmailVerificationRequest request) {
//        emailVerificationService.check(request.emailVerificationId(), request.code());
//    }

    private void writeAccessTokenCookie(HttpServletResponse response, String accessToken) {
        ResponseCookie cookie = ResponseCookie.from(ACCESS_TOKEN_COOKIE, accessToken)
                .httpOnly(true)
                .secure(true)
                .sameSite("Lax")
                .path("/")
                .maxAge(jwtProperties.accessTokenExpiry())
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    private void expireAccessTokenCookie(HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from(ACCESS_TOKEN_COOKIE, "")
                .httpOnly(true)
                .secure(true)
                .sameSite("Lax")
                .path("/")
                .maxAge(0)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    private ClientMetadata resolveClientMetadata(HttpServletRequest request) {
        String userAgent = request.getHeader(HttpHeaders.USER_AGENT);
        String ipAddressHeader = request.getHeader("X-Forwarded-For");
        String ipAddress = ipAddressHeader != null && !ipAddressHeader.isBlank()
                ? ipAddressHeader.split(",")[0].trim()
                : request.getRemoteAddr();
        return new ClientMetadata(userAgent, ipAddress);
    }
}
