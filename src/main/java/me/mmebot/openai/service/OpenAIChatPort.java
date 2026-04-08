package me.mmebot.openai.service;

import me.mmebot.openai.dto.ChatStreamResponse;
import reactor.core.publisher.Flux;

import java.util.List;
import java.util.Map;

/**
 * OpenAI 채팅 완료를 위한 스트리밍 우선 포트 인터페이스.
 * 구현체는 스트리밍 경로를 단일 진실(소스 오브 트루스)로 취급해야 한다.
 */
public interface OpenAIChatPort {

    /**
     * 메시지 목록에 대한 델타 청크 스트림을 반환한다.
     */
    Flux<ChatStreamResponse> summarizeStream(List<Map<String, String>> content);

    /**
     * 동기 편의 메서드: 스트림을 수집하여 단일 문자열로 합친다.
     * 내부적으로 스트림을 블로킹 수집할 수 있다.
     */
    default String summarizeSync(List<Map<String, String>> content) {
        return summarizeStream(content)
                .map(ChatStreamResponse::content)
                .collect(StringBuilder::new, StringBuilder::append)
                .map(StringBuilder::toString)
                .block();
    }
}
