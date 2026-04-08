package me.mmebot.common.logging;

public record MaskingStrategyConfig(
        MaskingStrategy strategy,
        Integer keepStart,
        Integer keepEnd,
        Character maskChar,
        Boolean preserveLength
) {
    public static MaskingStrategyConfig of(MaskingStrategy strategy, Integer keepStart, Integer keepEnd, Character maskChar, Boolean preserveLength) {
        return new MaskingStrategyConfig(strategy, keepStart, keepEnd, maskChar, preserveLength);
    }
}

