package me.mmebot.diary.domain;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter(autoApply = false)
public class VectorFloatArrayConverter implements AttributeConverter<float[], Object> {

    @Override
    public Object convertToDatabaseColumn(float[] attribute) {
        if (attribute == null) {
            return null;
        }
        if (attribute.length == 0) {
            return "[]";
        }
        StringBuilder builder = new StringBuilder(attribute.length * 6);
        builder.append('[');
        for (int i = 0; i < attribute.length; i++) {
            if (i > 0) {
                builder.append(',');
            }
            builder.append(attribute[i]);
        }
        builder.append(']');
        return builder.toString();
    }

    @Override
    public float[] convertToEntityAttribute(Object dbData) {
        if (dbData == null) {
            return null;
        }
        String content = dbData.toString().trim();
        if (content.isEmpty() || "[]".equals(content)) {
            return new float[0];
        }
        if (content.charAt(0) == '[' && content.charAt(content.length() - 1) == ']') {
            content = content.substring(1, content.length() - 1);
        }
        if (content.isBlank()) {
            return new float[0];
        }
        String[] parts = content.split(",");
        float[] result = new float[parts.length];
        for (int i = 0; i < parts.length; i++) {
            result[i] = Float.parseFloat(parts[i].trim());
        }
        return result;
    }
}
