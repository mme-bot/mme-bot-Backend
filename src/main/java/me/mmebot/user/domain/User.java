package me.mmebot.user.domain;

import java.time.OffsetDateTime;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class User {

    private Long id;
    private Long botId;
    private String emailHash;
    private String emailCipher;
    private String password;
    private String nickname;
    private boolean sns;
    private OffsetDateTime createdAt;
    private OffsetDateTime updatedAt;
    private OffsetDateTime deletedAt;

    public boolean isDeleted() {
        return deletedAt != null;
    }

    public boolean isActive() {
        return !isDeleted();
    }
}
