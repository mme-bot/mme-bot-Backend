package me.mmebot.openai.service;

import com.openai.client.OpenAIClient;
import com.openai.models.ChatModel;
import com.openai.models.chat.completions.ChatCompletion;
import com.openai.models.chat.completions.ChatCompletionCreateParams;
import lombok.RequiredArgsConstructor;
import me.mmebot.common.KoreanTextAnalyzer;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class OpenAiService {
    private final OpenAIClient openAIClient;
    private final KoreanTextAnalyzer analyzer;

    public String diarySummarizeShort(String content) {
        List<String> keywords = analyzer.extractKeywords(content);

        String prompt = """
    아래는 한국어 일기의 형태소 분석 결과입니다.
    입력된 키워드를 기반으로 가장 핵심적인 의미를 추출해
    최대 15개의 주요 키워드를 명사 중심으로 요약하세요.
    - 결과는 쉼표(,)로만 구분된 단일 라인으로 출력

    [형태소 분석 결과]
    %s
    """.formatted(keywords);

        System.out.println(prompt);
        return summarize(prompt);
    }

    private String summarize(String prompt) {
        ChatCompletionCreateParams params = ChatCompletionCreateParams.builder()
                .model(ChatModel.GPT_4_1_NANO) // 가성비 굿
                .addUserMessage(prompt)
                .build();

        ChatCompletion completion = openAIClient.chat().completions().create(params);

        return completion.choices().getFirst().message().content().orElseThrow(() -> new IllegalStateException("Error"));
    }
}
