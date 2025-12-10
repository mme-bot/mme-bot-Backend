package me.mmebot.common.logging;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.*;
import org.springframework.stereotype.Component;

@Slf4j
@Aspect
@Component
public class LoggingAspect {

    @Pointcut("within(@org.springframework.web.bind.annotation.RestController *)")
    public void restController() {}

    @Pointcut("within(me.mmebot..service..*)")
    public void serviceLayer() {}

    @Pointcut("restController() || serviceLayer()")
    public void applicationPackagePointcut() {}

    // 3) Around로 진입/종료 + 실행시간 로그
    @Around("applicationPackagePointcut()")
    public Object logAround(ProceedingJoinPoint joinPoint) throws Throwable {
        long start = System.currentTimeMillis();

        String className = joinPoint.getTarget().getClass().getSimpleName();
        String methodName = joinPoint.getSignature().getName();
        Object[] args = joinPoint.getArgs();

        log.info("[ENTER] {}.{} args={}", className, methodName, args);

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
}