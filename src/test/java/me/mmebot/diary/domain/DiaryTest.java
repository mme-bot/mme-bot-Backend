package me.mmebot.diary.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.LocalDate;
import java.time.OffsetDateTime;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Diary 도메인 테스트")
class DiaryTest {

    @Test
    @DisplayName("요청 사용자 ID가 일기 소유자 ID와 같으면 소유자로 판단한다")
    void isOwnedByReturnsTrueWhenUserIdMatchesOwnerId() {
        Diary diary = Diary.builder()
                .id(1L)
                .userId(10L)
                .build();

        assertThat(diary.isOwnedBy(10L)).isTrue();
    }

    @Test
    @DisplayName("요청 사용자 ID가 일기 소유자 ID와 다르면 소유자가 아니라고 판단한다")
    void isOwnedByReturnsFalseWhenUserIdDoesNotMatchOwnerId() {
        Diary diary = Diary.builder()
                .id(1L)
                .userId(10L)
                .build();

        assertThat(diary.isOwnedBy(20L)).isFalse();
    }

    @Test
    @DisplayName("일기 소유자 ID가 없으면 소유자가 아니라고 판단한다")
    void isOwnedByReturnsFalseWhenOwnerIdIsMissing() {
        Diary diary = Diary.builder()
                .id(1L)
                .build();

        assertThat(diary.isOwnedBy(10L)).isFalse();
    }

    @Test
    @DisplayName("요청 사용자 ID가 null이면 소유자가 아니라고 판단한다")
    void isOwnedByReturnsFalseWhenRequesterUserIdIsNull() {
        Diary diary = Diary.builder()
                .id(1L)
                .userId(10L)
                .build();

        assertThat(diary.isOwnedBy(null)).isFalse();
    }

    @Test
    @DisplayName("삭제 시간이 없으면 삭제되지 않은 활성 일기로 판단한다")
    void isActiveReturnsTrueWhenDiaryIsNotDeleted() {
        Diary diary = Diary.builder()
                .id(1L)
                .deletedAt(null)
                .build();

        assertThat(diary.isDeleted()).isFalse();
        assertThat(diary.isActive()).isTrue();
    }

    @Test
    @DisplayName("삭제 시간이 있으면 삭제된 비활성 일기로 판단한다")
    void isActiveReturnsFalseWhenDiaryIsDeleted() {
        Diary diary = Diary.builder()
                .id(1L)
                .deletedAt(OffsetDateTime.parse("2026-05-05T10:15:30+09:00"))
                .build();

        assertThat(diary.isDeleted()).isTrue();
        assertThat(diary.isActive()).isFalse();
    }

    @Test
    @DisplayName("일기 날짜가 기준 날짜와 같으면 채팅 시작 가능으로 판단한다")
    void isChatStartableOnReturnsTrueWhenDiaryDateMatchesDate() {
        LocalDate date = LocalDate.of(2026, 5, 5);
        Diary diary = Diary.builder()
                .id(1L)
                .date(date)
                .build();

        assertThat(diary.isChatStartableOn(date)).isTrue();
    }

    @Test
    @DisplayName("일기 날짜가 기준 날짜와 다르면 채팅 시작 불가로 판단한다")
    void isChatStartableOnReturnsFalseWhenDiaryDateDoesNotMatchDate() {
        Diary diary = Diary.builder()
                .id(1L)
                .date(LocalDate.of(2026, 5, 4))
                .build();

        assertThat(diary.isChatStartableOn(LocalDate.of(2026, 5, 5))).isFalse();
    }

    @Test
    @DisplayName("일기 날짜가 없으면 채팅 시작 불가로 판단한다")
    void isChatStartableOnReturnsFalseWhenDiaryDateIsMissing() {
        Diary diary = Diary.builder()
                .id(1L)
                .build();

        assertThat(diary.isChatStartableOn(LocalDate.of(2026, 5, 5))).isFalse();
    }
}
