package me.mmebot.auth.security;

import jakarta.servlet.http.HttpServletRequest;
import me.mmebot.auth.exception.AuthException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.AuthenticationPrincipal;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.method.support.ModelAndViewContainer;
import org.springframework.core.MethodParameter;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class StrictAuthenticationPrincipalArgumentResolverTest {

    private final StrictAuthenticationPrincipalArgumentResolver resolver =
            new StrictAuthenticationPrincipalArgumentResolver();

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void resolvesAuthenticatedUserId() throws Exception {
        SecurityContextHolder.getContext()
                .setAuthentication(new TestingAuthenticationToken(42L, null));

        Object resolved = resolver.resolveArgument(methodParameter(),
                new ModelAndViewContainer(),
                webRequest(),
                null);

        assertThat(resolved).isEqualTo(42L);
    }

    @Test
    void throwsWhenPrincipalMissing() {
        assertThatThrownBy(() -> resolver.resolveArgument(methodParameter(),
                new ModelAndViewContainer(),
                webRequest(),
                null))
                .isInstanceOf(AuthException.class);
    }

    private MethodParameter methodParameter() {
        Method method = ReflectionUtils.findMethod(SampleController.class, "handler", Long.class);
        return new MethodParameter(method, 0);
    }

    private NativeWebRequest webRequest() {
        HttpServletRequest request = new MockHttpServletRequest();
        return new ServletWebRequest(request);
    }

    private static final class SampleController {
        public void handler(@AuthenticationPrincipal Long userId) {
        }
    }
}
