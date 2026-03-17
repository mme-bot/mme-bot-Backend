package me.mmebot.common.logging;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.*;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;

import java.lang.reflect.Parameter;

@Slf4j
@Aspect
@Component
@RequiredArgsConstructor
public class LoggingAspect {

    private final MaskingProperties maskingProperties;

    @Pointcut("within(@org.springframework.web.bind.annotation.RestController *)")
    public void restController() {}

    @Pointcut("within(me.mmebot..service..*)")
    public void serviceLayer() {}

    @Pointcut("restController() || serviceLayer()")
    public void applicationPackagePointcut() {}

    @Around("applicationPackagePointcut()")
    public Object logAround(ProceedingJoinPoint joinPoint) throws Throwable {
        long start = System.currentTimeMillis();

        String className = joinPoint.getTarget().getClass().getSimpleName();
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        String methodName = signature.getName();

        String argsString = renderArgs(signature, joinPoint.getArgs());
        log.info("[ENTER] {}.{} args={}", className, methodName, argsString);

        try {
            Object result = joinPoint.proceed();
            long elapsed = System.currentTimeMillis() - start;

            if (log.isInfoEnabled()) {
                log.info("[EXIT] {}.{} elapsed={}ms resultType={}",
                        className, methodName, elapsed,
                        result != null ? result.getClass().getSimpleName() : "null"
                );
            }
            return result;
        } catch (Throwable ex) {
            long elapsed = System.currentTimeMillis() - start;
            log.error("[ERROR] {}.{} elapsed={}ms ex={}",
                    className, methodName, elapsed, ex.getMessage());
            throw ex;
        }
    }

    private String renderArgs(MethodSignature signature, Object[] args) {
        try {
            if (!maskingProperties.maskingEnabled()) {
                return MaskingUtil.simpleArgs(signature.getParameterNames(), args);
            }
            Parameter[] params = signature.getMethod().getParameters();
            return MaskingUtil.maskedArgs(params, args, maskingProperties);
        } catch (Throwable t) {
            // Fallback to safe minimal logging on any error
            return "<args unavailable>";
        }
    }

}
