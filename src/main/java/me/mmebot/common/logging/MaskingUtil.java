package me.mmebot.common.logging;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.aspectj.lang.reflect.MethodSignature;

import java.lang.reflect.Field;
import java.lang.reflect.Parameter;
import java.time.temporal.Temporal;
import java.util.*;

final class MaskingUtil {
    private static final int MAX_COLLECTION_ITEMS = 10;

    private MaskingUtil() {}

    static String simpleArgs(String[] names, Object[] values) {
        if (values == null || values.length == 0) return "[]";
        List<String> parts = new ArrayList<>();
        for (int i = 0; i < values.length; i++) {
            String name = names != null && i < names.length ? names[i] : ("arg" + i);
            String rendered = String.valueOf(values[i]);
            parts.add(name + "=" + rendered);
        }
        return parts.toString();
    }

    static String maskedArgs(Parameter[] params, Object[] args, MaskingProperties props) {
        if (args == null || args.length == 0) return "[]";
        List<String> parts = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            Parameter p = (params != null && i < params.length) ? params[i] : null;
            String name = p != null ? p.getName() : ("arg" + i);
            Masked ann = p != null ? p.getAnnotation(Masked.class) : null;
            String rendered = renderValue(args[i], name, ann, props, 0, new IdentityHashMap<>());
            parts.add(name + "=" + rendered);
        }
        return parts.toString();
    }

    private static String renderValue(Object value,
                                      String name,
                                      Masked paramAnnotation,
                                      MaskingProperties props,
                                      int depth,
                                      Map<Object, Boolean> visited) {
        if (value == null) return "null";

        // Apply masking rule if any
        MaskingStrategyConfig rule = resolveRule(name, paramAnnotation, props);
        if (rule != null) {
            if (value instanceof CharSequence cs) {
                return applyMask(name, cs.toString(), rule);
            }
            return "***";
        }

        if (value instanceof CharSequence) return value.toString();
        if (value instanceof Number || value instanceof Boolean || value instanceof Enum<?> || value instanceof Temporal) {
            return String.valueOf(value);
        }
        if (value instanceof byte[]) return "byte[" + ((byte[]) value).length + "]";
        if (value instanceof char[]) return "char[" + ((char[]) value).length + "]";
        if (value.getClass().isArray()) {
            int len = java.lang.reflect.Array.getLength(value);
            List<String> items = new ArrayList<>();
            for (int i = 0; i < Math.min(len, MAX_COLLECTION_ITEMS); i++) {
                Object el = java.lang.reflect.Array.get(value, i);
                items.add(renderValue(el, name, null, props, depth + 1, visited));
            }
            if (len > MAX_COLLECTION_ITEMS) items.add("…" + (len - MAX_COLLECTION_ITEMS) + " more");
            return items.toString();
        }
        if (value instanceof Collection<?> col) {
            List<String> items = new ArrayList<>();
            int i = 0;
            for (Object el : col) {
                if (i++ >= MAX_COLLECTION_ITEMS) { items.add("…" + (col.size() - MAX_COLLECTION_ITEMS) + " more"); break; }
                items.add(renderValue(el, name, null, props, depth + 1, visited));
            }
            return items.toString();
        }
        if (value instanceof Map<?,?> map) {
            List<String> items = new ArrayList<>();
            int i = 0;
            for (Map.Entry<?,?> e : map.entrySet()) {
                if (i++ >= MAX_COLLECTION_ITEMS) { items.add("…" + (map.size() - MAX_COLLECTION_ITEMS) + " more"); break; }
                String key = String.valueOf(e.getKey());
                MaskingStrategyConfig keyRule = resolveRule(key, null, props);
                if (keyRule != null) {
                    Object val = e.getValue();
                    if (val instanceof CharSequence cs) {
                        items.add(key + "=" + applyMask(key, cs.toString(), keyRule));
                    } else {
                        items.add(key + "=***");
                    }
                } else {
                    items.add(key + "=" + renderValue(e.getValue(), key, null, props, depth + 1, visited));
                }
            }
            return items.toString();
        }

        if (value instanceof HttpServletRequest || value instanceof HttpServletResponse) {
            return value.getClass().getSimpleName();
        }

        if (depth >= 2) return value.getClass().getSimpleName();
        if (visited.containsKey(value)) return value.getClass().getSimpleName();
        visited.put(value, Boolean.TRUE);

        // If record: use record components to detect @MaskedField and extract values
        if (value.getClass().isRecord()) {
            List<String> parts = new ArrayList<>();
            for (var rc : value.getClass().getRecordComponents()) {
                String cname = rc.getName();
                MaskedField ann = rc.getAnnotation(MaskedField.class);
                try {
                    Object cv = rc.getAccessor().invoke(value);
                    MaskingStrategyConfig ruleRc = resolveRule(cname, ann, props);
                    if (ruleRc != null && cv instanceof CharSequence cs) {
                        parts.add(cname + "=" + applyMask(cname, cs.toString(), ruleRc));
                    } else if (ruleRc != null) {
                        parts.add(cname + "=***");
                    } else {
                        parts.add(cname + "=" + renderValue(cv, cname, null, props, depth + 1, visited));
                    }
                } catch (Throwable e) {
                    parts.add(cname + "=<inaccessible>");
                }
            }
            return value.getClass().getSimpleName() + "{" + String.join(", ", parts) + "}";
        }

        // Try to render fields, masking sensitive names and @MaskedField
        List<String> fieldsOut = new ArrayList<>();
        for (Field f : getAllFields(value.getClass())) {
            f.setAccessible(true);
            String fname = f.getName();
            MaskedField ann = f.getAnnotation(MaskedField.class);
            try {
                Object fv = f.get(value);
                MaskingStrategyConfig ruleField = resolveRule(fname, ann, props);
                if (ruleField != null && fv instanceof CharSequence cs) {
                    fieldsOut.add(fname + "=" + applyMask(fname, cs.toString(), ruleField));
                } else if (ruleField != null) {
                    fieldsOut.add(fname + "=***");
                } else {
                    fieldsOut.add(fname + "=" + renderValue(fv, fname, null, props, depth + 1, visited));
                }
            } catch (IllegalAccessException e) {
                fieldsOut.add(fname + "=<inaccessible>");
            }
        }
        return value.getClass().getSimpleName() + "{" + String.join(", ", fieldsOut) + "}";
    }

    private static MaskingStrategyConfig resolveRule(String name, Masked paramAnn, MaskingProperties props) {
        if (paramAnn != null) {
            if (paramAnn.strategy() != null && paramAnn.strategy() != MaskingStrategy.AUTO) {
                return new MaskingStrategyConfig(
                        paramAnn.strategy(),
                        paramAnn.keepStart(),
                        paramAnn.keepEnd(),
                        paramAnn.maskChar(),
                        paramAnn.preserveLength()
                );
            }
            // AUTO: prefer configured strategy; else fallback FULL
            MaskingStrategyConfig cfg = props.sensitiveStrategiesOrDefault().get(name);
            if (cfg != null) return cfg;
            return new MaskingStrategyConfig(MaskingStrategy.FULL, 0, 0, '*', false);
        }
        // No annotation, try configured strategy by name
        MaskingStrategyConfig cfg = props.sensitiveStrategiesOrDefault().get(name);
        if (cfg != null) return cfg;
        // Fallback to full mask if name in sensitive list
        if (isSensitiveKey(name, props)) {
            return new MaskingStrategyConfig(MaskingStrategy.FULL, 0, 0, '*', false);
        }
        return null;
    }

    private static MaskingStrategyConfig resolveRule(String name, MaskedField fieldAnn, MaskingProperties props) {
        if (fieldAnn != null) {
            if (fieldAnn.strategy() != null && fieldAnn.strategy() != MaskingStrategy.AUTO) {
                return new MaskingStrategyConfig(
                        fieldAnn.strategy(),
                        fieldAnn.keepStart(),
                        fieldAnn.keepEnd(),
                        fieldAnn.maskChar(),
                        fieldAnn.preserveLength()
                );
            }
            MaskingStrategyConfig cfg = props.sensitiveStrategiesOrDefault().get(name);
            if (cfg != null) return cfg;
            return new MaskingStrategyConfig(MaskingStrategy.FULL, 0, 0, '*', false);
        }
        MaskingStrategyConfig cfg = props.sensitiveStrategiesOrDefault().get(name);
        if (cfg != null) return cfg;
        if (isSensitiveKey(name, props)) {
            return new MaskingStrategyConfig(MaskingStrategy.FULL, 0, 0, '*', false);
        }
        return null;
    }

    private static boolean isSensitiveKey(String name, MaskingProperties props) {
        if (name == null) return false;
        String n = name.toLowerCase(Locale.ROOT);
        for (String s : props.sensitiveKeysOrDefault()) {
            if (n.equals(s.toLowerCase(Locale.ROOT))) return true;
        }
        return false;
    }

    private static String applyMask(String name, String value, MaskingStrategyConfig rule) {
        if (value == null) return null;
        MaskingStrategy strategy = rule.strategy() != null ? rule.strategy() : MaskingStrategy.FULL;
        int keepStart = rule.keepStart() != null ? Math.max(0, rule.keepStart()) : 0;
        int keepEnd = rule.keepEnd() != null ? Math.max(0, rule.keepEnd()) : 0;
        char ch = rule.maskChar() != null ? rule.maskChar() : '*';
        boolean preserveLength = rule.preserveLength() != null && rule.preserveLength();

        String v = value;
        boolean hasBearer = false;
        if ("authorization".equalsIgnoreCase(name) && value.regionMatches(true, 0, "Bearer ", 0, 7)) {
            v = value.substring(7).trim();
            hasBearer = true;
        }

        String masked;
        switch (strategy) {
            case FULL -> masked = "***";
            case PARTIAL -> masked = maskPartial(v, keepStart, keepEnd, ch, preserveLength);
            case EMAIL -> masked = maskEmail(v, ch);
            case JWT -> masked = maskJwt(v);
            case HASHED -> masked = maskHashed(v);
            case AUTO -> masked = "***";
            default -> masked = "***";
        }

        if (hasBearer) return "Bearer " + masked;
        return masked;
    }

    private static String maskPartial(String v, int keepStart, int keepEnd, char ch, boolean preserveLength) {
        if (v == null) return null;
        int n = v.length();
        if (n <= keepStart + keepEnd) return "***";
        String head = keepStart > 0 ? v.substring(0, keepStart) : "";
        String tail = keepEnd > 0 ? v.substring(n - keepEnd) : "";
        if (preserveLength) {
            int mid = n - head.length() - tail.length();
            char[] buf = new char[mid];
            Arrays.fill(buf, ch);
            return head + new String(buf) + tail;
        }
        return head + "***" + tail;
    }

    private static String maskEmail(String v, char ch) {
        int at = v.indexOf('@');
        if (at < 0) return "***"; // not an email, fallback
        String local = v.substring(0, at);
        String domain = v.substring(at);
        if (local.length() <= 2) return "**" + domain;
        return local.substring(0, 2) + "***" + domain;
    }

    private static String maskJwt(String v) {
        if (v == null) return null;
        if (v.length() <= 12) return "***";
        return v.substring(0, 6) + "…" + v.substring(v.length() - 6);
    }

    private static String maskHashed(String v) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] dig = md.digest(v.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8 && i < dig.length; i++) {
                sb.append(String.format("%02x", dig[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            return "***";
        }
    }

    private static List<Field> getAllFields(Class<?> type) {
        List<Field> fields = new ArrayList<>();
        Class<?> t = type;
        while (t != null && t != Object.class) {
            fields.addAll(Arrays.asList(t.getDeclaredFields()));
            t = t.getSuperclass();
        }
        return fields;
    }

}
