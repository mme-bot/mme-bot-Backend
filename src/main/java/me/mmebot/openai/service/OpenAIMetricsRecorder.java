package me.mmebot.openai.service;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

/**
 * OpenAI 호출 메트릭 기록기.
 * MeterRegistry 가 없으면 안전하게 no-op 으로 동작한다.
 */
@Component
public class OpenAIMetricsRecorder {

    private final MeterRegistry meterRegistry; // nullable

    public OpenAIMetricsRecorder(ObjectProvider<MeterRegistry> meterRegistryProvider) {
        this.meterRegistry = meterRegistryProvider.getIfAvailable();
    }

    /**
     * 스트림 TTFB(ms) 기록.
     */
    public void recordTtfb(String model, double millis) {
        if (meterRegistry == null || millis < 0) return;
        DistributionSummary.builder("openai.stream.ttfb.ms")
                .baseUnit("milliseconds")
                .tag("model", model)
                .register(meterRegistry)
                .record(millis);
    }

    /**
     * 스트림 총 소요시간(ms) 기록.
     */
    public void recordDuration(String model, double millis) {
        if (meterRegistry == null) return;
        DistributionSummary.builder("openai.stream.duration.ms")
                .baseUnit("milliseconds")
                .tag("model", model)
                .register(meterRegistry)
                .record(millis);
    }

    /**
     * 토큰 사용량 기록.
     */
    public void recordTokenUsage(String model, long prompt, long completion, long total) {
        if (meterRegistry == null) return;
        increment("openai.tokens.prompt", model, prompt);
        increment("openai.tokens.completion", model, completion);
        increment("openai.tokens.total", model, total);
    }

    private void increment(String name, String model, double value) {
        if (value <= 0) return;
        Counter.builder(name)
                .tag("model", model)
                .register(meterRegistry)
                .increment(value);
    }
}

