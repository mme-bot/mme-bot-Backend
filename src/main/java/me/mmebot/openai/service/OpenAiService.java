package me.mmebot.openai.service;

import com.openai.client.OpenAIClient;
import com.openai.client.okhttp.OpenAIOkHttpClient;
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
                다음은 한국어 일기를 형태소 분석한 결과입니다. 핵심 키워드를 10개 이내로 요약하세요.
                분석 결과는 단어를 나열하고 사이에 쉼표를 붙입니다.
                [형태소 분석 키워드]
                %s
                """.formatted(keywords);

        System.out.println(prompt);
        return summarize(prompt);
    }

    private String summarize(String prompt) {
        ChatCompletionCreateParams params = ChatCompletionCreateParams.builder()
                .model(ChatModel.GPT_4O_MINI) // 가성비 굿
                .addUserMessage(prompt)
                .build();

        ChatCompletion completion = openAIClient.chat().completions().create(params);

        return completion.choices().getFirst().message().content().orElseThrow(() -> new IllegalStateException("Error"));
    }
}
