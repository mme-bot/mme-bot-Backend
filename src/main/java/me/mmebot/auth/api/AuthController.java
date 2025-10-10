package me.mmebot.auth.api;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import me.mmebot.auth.api.dto.CheckEmailVerificationRequest;
import me.mmebot.auth.api.dto.SendEmailVerificationRequest;
import me.mmebot.auth.api.dto.SendEmailVerificationResponse;
import me.mmebot.auth.api.dto.SignInRequest;
import me.mmebot.auth.api.dto.SignInResponse;
import me.mmebot.auth.api.dto.SignUpRequest;
import me.mmebot.auth.api.dto.TokenReissueRequest;
import me.mmebot.auth.api.dto.TokenReissueResponse;
import me.mmebot.auth.service.AuthService;
import me.mmebot.auth.service.EmailVerificationService;
import me.mmebot.common.config.JwtProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("${api.base-path:/api}/auth")
public class AuthController {

    private static final String ACCESS_TOKEN_COOKIE = "access_token";

    private final AuthService authService;
    private final EmailVerificationService emailVerificationService;
    private final JwtProperties jwtProperties;

    public AuthController(AuthService authService,
                          EmailVerificationService emailVerificationService,
                          JwtProperties jwtProperties) {
        this.authService = authService;
        this.emailVerificationService = emailVerificationService;
        this.jwtProperties = jwtProperties;
    }

    @PostMapping("/sign-in")
    public SignInResponse signIn(@Valid @RequestBody SignInRequest request,
                                 HttpServletRequest httpRequest,
                                 HttpServletResponse httpResponse) {
        AuthService.SignInResult result = authService.signIn(request.email(), request.passwd(),
                resolveClientMetadata(httpRequest));
        writeAccessTokenCookie(httpResponse, result.accessToken());
        return new SignInResponse(result.userId(), result.botId(), result.nickname(),
                result.accessToken(), result.refreshToken());
    }

    @PostMapping("/sign-up")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void signUp(@Valid @RequestBody SignUpRequest request) {
        authService.signUp(new AuthService.SignUpCommand(
                request.email(),
                request.passwd(),
                request.nickname(),
                request.emailVerificationId()
        ));
    }

    @PostMapping("/email-verification/send")
    public SendEmailVerificationResponse sendEmailVerification(@Valid @RequestBody SendEmailVerificationRequest request) {
        EmailVerificationService.SendEmailVerificationResult result = emailVerificationService.send(request.email());
        return new SendEmailVerificationResponse(result.emailVerificationId(), result.code());
    }

    @PostMapping("/email-verification/check")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void checkEmailVerification(@Valid @RequestBody CheckEmailVerificationRequest request) {
        emailVerificationService.check(request.emailVerificationId(), request.code());
    }

    @PostMapping("/token-reissue")
    public TokenReissueResponse reissueToken(@Valid @RequestBody TokenReissueRequest request,
                                             HttpServletRequest httpRequest,
                                             HttpServletResponse httpResponse) {
        AuthService.TokenPair tokens = authService.reissue(request.userId(), request.refreshToken(),
                resolveClientMetadata(httpRequest));
        writeAccessTokenCookie(httpResponse, tokens.accessToken());
        return new TokenReissueResponse(tokens.accessToken(), tokens.refreshToken());
    }

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

    private AuthService.ClientMetadata resolveClientMetadata(HttpServletRequest request) {
        String userAgent = request.getHeader(HttpHeaders.USER_AGENT);
        String ipAddressHeader = request.getHeader("X-Forwarded-For");
        String ipAddress = ipAddressHeader != null && !ipAddressHeader.isBlank()
                ? ipAddressHeader.split(",")[0].trim()
                : request.getRemoteAddr();
        return new AuthService.ClientMetadata(userAgent, ipAddress);
    }
}
