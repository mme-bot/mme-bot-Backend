package me.mmebot.common.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class ValidEmailValidator implements ConstraintValidator<ValidEmail, String> {

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || value.isBlank()) {
            return true;
        }

        int atIndex = value.indexOf('@');
        if (atIndex <= 0 || atIndex != value.lastIndexOf('@')) {
            return false;
        }

        String localPart = value.substring(0, atIndex);
        String domainPart = value.substring(atIndex + 1);
        if (localPart.isBlank() || domainPart.isBlank()) {
            return false;
        }

        if (domainPart.startsWith(".") || domainPart.endsWith(".")) {
            return false;
        }

        if (!domainPart.contains(".")) {
            return false;
        }

        String[] domainSections = domainPart.split("\\.");
        for (String section : domainSections) {
            if (section.isBlank()) {
                return false;
            }
        }

        return true;
    }
}
