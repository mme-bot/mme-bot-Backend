package me.mmebot.user.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("NormalizedEmail 도메인 테스트")
class NormalizedEmailTest {

    @Test
    @DisplayName("이메일 앞뒤 공백을 제거하고 소문자로 정규화한다")
    void fromTrimsAndLowercasesEmail() {
        NormalizedEmail email = NormalizedEmail.from("  USER@Example.COM  ");

        assertThat(email.value()).isEqualTo("user@example.com");
    }

    @Test
    @DisplayName("null 이메일은 생성할 수 없다")
    void fromRejectsNullEmail() {
        assertThatThrownBy(() -> NormalizedEmail.from(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Email must not be blank");
    }

    @Test
    @DisplayName("빈 이메일은 생성할 수 없다")
    void fromRejectsBlankEmail() {
        assertThatThrownBy(() -> NormalizedEmail.from("   "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Email must not be blank");
    }
}
