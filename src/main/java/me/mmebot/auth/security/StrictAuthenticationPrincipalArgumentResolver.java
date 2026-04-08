package me.mmebot.auth.security;

import me.mmebot.auth.exception.AuthException;
import org.springframework.core.MethodParameter;
import org.springframework.security.web.method.annotation.AuthenticationPrincipalArgumentResolver;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

@Component
public class StrictAuthenticationPrincipalArgumentResolver implements HandlerMethodArgumentResolver {

    private final AuthenticationPrincipalArgumentResolver delegate = new AuthenticationPrincipalArgumentResolver();

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return delegate.supportsParameter(parameter);
    }

    @Override
    public Object resolveArgument(MethodParameter parameter,
                                  ModelAndViewContainer mavContainer,
                                  NativeWebRequest webRequest,
                                  WebDataBinderFactory binderFactory) throws Exception {
        Object principal = delegate.resolveArgument(parameter, mavContainer, webRequest, binderFactory);
        if (principal == null) {
            throw AuthException.authenticationRequired();
        }
        return principal;
    }
}
