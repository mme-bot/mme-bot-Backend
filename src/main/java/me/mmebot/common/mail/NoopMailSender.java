package me.mmebot.common.mail;

import lombok.extern.slf4j.Slf4j;

@Slf4j
class NoopMailSender implements MailSender {

    @Override
    public void send(MailMessage message) {
        log.info("Mail sending disabled. Skipping email to {} with subject {}", message.to(), message.subject());
    }
}
