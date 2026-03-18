package me.mmebot.common.logging;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@ConfigurationProperties(prefix = "logging.aspect")
public record MaskingProperties(
        Boolean maskingEnabled,
        List<String> sensitiveKeys,
        Map<String, MaskingStrategyConfig> sensitiveStrategies
) {
    public boolean isMaskingEnabled() {
        return maskingEnabled != null ? maskingEnabled : true;
    }

    public List<String> sensitiveKeysOrDefault() {
        if (sensitiveKeys == null || sensitiveKeys.isEmpty()) {
            return List.of(
                    "password", "passwd", "accessToken", "refreshToken",
                    "token", "authorization", "code", "secret", "clientSecret"
            );
        }
        return sensitiveKeys;
    }

    public Map<String, MaskingStrategyConfig> sensitiveStrategiesOrDefault() {
        if (sensitiveStrategies != null && !sensitiveStrategies.isEmpty()) return sensitiveStrategies;
        Map<String, MaskingStrategyConfig> defaults = new HashMap<>();
        defaults.put("email", new MaskingStrategyConfig(MaskingStrategy.EMAIL, null, null, null, null));
        defaults.put("accessToken", new MaskingStrategyConfig(MaskingStrategy.PARTIAL, 0, 4, '*', false));
        defaults.put("refreshToken", new MaskingStrategyConfig(MaskingStrategy.PARTIAL, 0, 4, '*', false));
        defaults.put("token", new MaskingStrategyConfig(MaskingStrategy.PARTIAL, 0, 4, '*', false));
        defaults.put("authorization", new MaskingStrategyConfig(MaskingStrategy.PARTIAL, 0, 6, '*', false));
        defaults.put("code", new MaskingStrategyConfig(MaskingStrategy.PARTIAL, 0, 2, '*', false));
        return defaults;
    }

}
