package me.mmebot.common.mail;

import org.springframework.http.MediaType;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public record MailMessage(
        List<String> to,
        List<String> cc,
        List<String> bcc,
        String subject,
        String body,
        MediaType contentType
) {

    public MailMessage {
        to = normalizeRecipients(to, "to", true);
        cc = normalizeRecipients(cc, "cc", false);
        bcc = normalizeRecipients(bcc, "bcc", false);
        subject = requireNonBlank(subject, "subject");
        body = Objects.requireNonNull(body, "body");
        contentType = contentType == null ? MediaType.TEXT_PLAIN : contentType;
    }

    public MailMessage(List<String> to, String subject, String body) {
        this(to, List.of(), List.of(), subject, body, MediaType.TEXT_PLAIN);
    }

    public static MailMessage plainText(String to, String subject, String body) {
        return new MailMessage(List.of(requireNonBlank(to, "to")), List.of(), List.of(), subject, body,
                MediaType.TEXT_PLAIN);
    }

    public static MailMessage html(String to, String subject, String body) {
        return new MailMessage(List.of(requireNonBlank(to, "to")), List.of(), List.of(), subject, body,
                MediaType.TEXT_HTML);
    }

    private static List<String> normalizeRecipients(List<String> recipients, String label, boolean required) {
        if (recipients == null || recipients.isEmpty()) {
            if (required) {
                throw new IllegalArgumentException(label + " recipients are required");
            }
            return List.of();
        }
        List<String> result = new ArrayList<>(recipients.size());
        for (String recipient : recipients) {
            result.add(requireNonBlank(recipient, label + " recipient"));
        }
        return Collections.unmodifiableList(result);
    }

    private static String requireNonBlank(String value, String label) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(label + " is required");
        }
        return value.trim();
    }
}
