package me.mmebot.diary.domain;

import java.time.LocalDate;
import java.time.OffsetDateTime;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class Diary {

    private final Long id;
    private final Long userId;
    private final String content;
    private final String emotion;
    private final String summaryShort;
    private final LocalDate date;
    private final OffsetDateTime createdAt;
    private final OffsetDateTime updatedAt;
    private final OffsetDateTime deletedAt;

    public boolean isDeleted() {
        return deletedAt != null;
    }

    public boolean isActive() {
        return !isDeleted();
    }

    public boolean isOwnedBy(Long userId) {
        return this.userId != null && this.userId.equals(userId);
    }

    public boolean isChatStartableOn(LocalDate date) {
        return this.date != null && this.date.isEqual(date);
    }

    public Diary update(String content, String emotion, String summaryShort, LocalDate date) {
        return Diary.builder()
                .id(this.id)
                .userId(this.userId)
                .content(content)
                .emotion(emotion)
                .summaryShort(summaryShort)
                .date(date)
                .createdAt(this.createdAt)
                .updatedAt(this.updatedAt)
                .deletedAt(this.deletedAt)
                .build();
    }

    public Diary markDeleted(OffsetDateTime deletedAt) {
        return Diary.builder()
                .id(this.id)
                .userId(this.userId)
                .content(this.content)
                .emotion(this.emotion)
                .summaryShort(this.summaryShort)
                .date(this.date)
                .createdAt(this.createdAt)
                .updatedAt(this.updatedAt)
                .deletedAt(deletedAt)
                .build();
    }
}
