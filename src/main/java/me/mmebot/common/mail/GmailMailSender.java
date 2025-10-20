package me.mmebot.common.mail;

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Properties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;

@Slf4j
class GmailMailSender implements MailSender {

    private static final JsonFactory JSON_FACTORY = GsonFactory.getDefaultInstance();

    private final Gmail gmail;
    private final GoogleCredential credential;
    private final Session mailSession;
    private final InternetAddress fromAddress;

    GmailMailSender(GoogleProperties properties) {
        Objects.requireNonNull(properties, "properties");
        this.mailSession = Session.getInstance(new Properties());
        this.credential = createCredential(properties);
        this.gmail = createGmailClient(credential, properties);
        this.fromAddress = createFromAddress(properties);
    }

    @Override
    public void send(MailMessage message) {
        Objects.requireNonNull(message, "message");
        try {
            ensureAccessToken();
            MimeMessage mimeMessage = buildMimeMessage(message);
            Message gmailMessage = wrapMimeMessage(mimeMessage);
            Message result = gmail.users().messages().send("me", gmailMessage).execute(); // "me" 이 코드를 실행 중인 인증된 gmail 사용자
            log.info("Gmail message sent. id={}, to={}, subject={}", result.getId(), message.to(), message.subject());
        } catch (MessagingException | IOException ex) {
            log.error(ex.getMessage(), ex);
            throw new MailSendingException("Failed to send email via Gmail API", ex);
        }
    }

    private MimeMessage buildMimeMessage(MailMessage message) throws MessagingException {
        MimeMessage mimeMessage = new MimeMessage(mailSession);
        mimeMessage.setFrom(fromAddress);
        addRecipients(mimeMessage, jakarta.mail.Message.RecipientType.TO, message.to());
        addRecipients(mimeMessage, jakarta.mail.Message.RecipientType.CC, message.cc());
        addRecipients(mimeMessage, jakarta.mail.Message.RecipientType.BCC, message.bcc());
        mimeMessage.setSubject(message.subject(), StandardCharsets.UTF_8.name());
        if (message.contentType() == MediaType.TEXT_HTML) {
            mimeMessage.setContent(message.body(), message.contentType() + "; charset=UTF-8");
        } else {
            mimeMessage.setText(message.body(), StandardCharsets.UTF_8.name());
        }
        return mimeMessage;
    }

    private void addRecipients(MimeMessage mimeMessage, jakarta.mail.Message.RecipientType type, List<String> recipients)
            throws MessagingException {
        for (String address : recipients) {
            mimeMessage.addRecipient(type, new InternetAddress(address));
        }
    }

    private Message wrapMimeMessage(MimeMessage mimeMessage) throws MessagingException, IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        mimeMessage.writeTo(buffer);
        byte[] bytes = buffer.toByteArray();
        String encodedEmail = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        Message gmailMessage = new Message();
        gmailMessage.setRaw(encodedEmail);
        return gmailMessage;
    }

    private void ensureAccessToken() {
        if (credential.getAccessToken() == null) {
            refreshCredential(credential);
        }
    }

    private GoogleCredential createCredential(GoogleProperties properties) {
        try {
            HttpTransport transport = GoogleNetHttpTransport.newTrustedTransport();
            GoogleCredential credential = new GoogleCredential.Builder()
                    .setTransport(transport)
                    .setJsonFactory(JSON_FACTORY)
                    .setClientSecrets(requireNonBlank(properties.clientId(), "gmail.client-id"),
                            requireNonBlank(properties.clientSecret(), "gmail.client-secret"))
                    .build();
            credential.setRefreshToken(requireNonBlank(properties.refreshToken(), "gmail.refresh-token"));
            refreshCredential(credential);
            log.info("Gmail credentials initialized for user {}", properties.userEmail());
            return credential;
        } catch (GeneralSecurityException | IOException ex) {
            log.error("Failed to create Gmail credentials", ex);
            throw new MailSendingException("Failed to initialize Gmail credentials", ex);
        }
    }

    private Gmail createGmailClient(GoogleCredential credential, GoogleProperties properties) {
        Gmail gmailClient = new Gmail.Builder(credential.getTransport(), JSON_FACTORY, credential)
                .setApplicationName(requireNonBlank(properties.applicationName(), "gmail.application-name"))
                .build();
        log.info("Gmail client configured for application {}", properties.applicationName());
        return gmailClient;
    }

    private InternetAddress createFromAddress(GoogleProperties properties) {
        try {
            String address = requireNonBlank(properties.userEmail(), "gmail.user-email");
            String personal = properties.fromDisplayName();
            if (personal == null || personal.isBlank()) {
                log.error("Gmail user email is null or blank");
                return new InternetAddress(address);
            }
            return new InternetAddress(address, personal);
        } catch (Exception ex) {
            log.error("Gmail user email is null or blank", ex);
            throw new MailSendingException("Failed to configure Gmail sender address", ex);
        }
    }

    private String requireNonBlank(String value, String label) {
        if (value == null || value.trim().isEmpty()) {
            log.error("{} is null or blank", label);
            throw new MailSendingException(label + " is required");
        }
        return value.trim();
    }

    private void refreshCredential(GoogleCredential credential) {
        try {
            if (!credential.refreshToken()) {
                log.error("Failed to refresh Gmail credential");
                throw new MailSendingException("Failed to refresh Gmail access token");
            }
        } catch (IOException ex) {
            log.error("Server exception", ex);
            throw new MailSendingException("Failed to refresh Gmail credential", ex);
        }
    }

}
