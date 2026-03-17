package me.mmebot.common.logging;

public enum MaskingStrategy {
    AUTO,    // Use config or defaults
    FULL,    // Replace with ***
    PARTIAL, // Keep head/tail, mask middle
    EMAIL,   // Hide most of local-part
    JWT,     // Shorten typical JWT strings
    HASHED   // Replace with short stable hash
}

