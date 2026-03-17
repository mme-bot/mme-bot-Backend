package me.mmebot.common.logging;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD, ElementType.RECORD_COMPONENT})
public @interface MaskedField {
    MaskingStrategy strategy() default MaskingStrategy.AUTO;
    int keepStart() default 0;
    int keepEnd() default 0;
    char maskChar() default '*';
    boolean preserveLength() default false;
}
