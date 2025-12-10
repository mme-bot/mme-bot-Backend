package me.mmebot.openai.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.openai.client.OpenAIClient;
import com.openai.models.ChatModel;
import com.openai.models.chat.completions.ChatCompletion;
import com.openai.models.chat.completions.ChatCompletionCreateParams;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.chat.domain.ChatMessage;
import me.mmebot.common.KoreanTextAnalyzer;
import me.mmebot.openai.dto.OpenAIChatMessage;
import me.mmebot.openai.exception.OpenAIException;
import org.springframework.stereotype.Service;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class OpenAIService {
    private final ObjectMapper mapper;
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

        return completion.choices().getFirst().message().content().orElseThrow(() -> {
            log.error("OpenAI completion missing content. Prompt: {}, completion: {}", prompt, completion);
            return OpenAIException.missingCompletionContent();
        });
    }

    public String sendChatMessage(
//            String botScript,
                                  String diarySummaryShort, List<ChatMessage> chatMessageList, String reqMessage) {
        List<OpenAIChatMessage> messageList = chatMessageList.stream().map(message ->
                new OpenAIChatMessage(
                        message.getRole(),
                        message.getContent()
                )).toList();

//        String messageStr = objToJson(messageList);

        String prompt = """
                [페르소나 규칙]
                당신은 기가차드(GigaChad) 스타일로 말하는 AI다.
                1) 말투는 강인하고 단호하며 자신감 넘쳐야 한다.
                2) 감탄사, 절대적 표현(“완벽하다”, “틀림없다”)을 자주 사용하며, 자신을 최정상으로 여긴다.
                3) 상대방을 강하게 긍정하고 동기부여한다.
                4) 전문적인 설명을 해도 기가차드 톤을 유지한다.
                5) 유머는 진지한 척하지만 과장되게.
                6) 이모티콘, 귀여운 표현, 가벼운 말투 사용 금지.
                7) 규칙은 모든 응답에 적용되며 예외가 없다.
                
                [대화 목적 규칙 - 매우 중요]
                1) 당신은 **일상 대화 및 감정 기반** 동반자다.
                2) 일반적인 지식, 정보, 분석, 검색, 번역, 프로그래밍 등
                   **일반 GPT 기능은 절대 수행하지 않는다.** 요청 시 페르소나 톤으로 거부한다.
                3) 허용된 목적: 감정 공감, 동기부여, 일상 이야기, 유머, 가벼운 고민 상담.
                4) “나는 정보 제공 AI가 아니다”라는 태도를 고집한다.
                
                [일기 기반 상호작용 규칙 - 핵심]
                1) “일기에 기반한 키워드”가 지속적으로 주어진다.
                2) 이 키워드는 사용자의 감정, 하루의 경험, 고민을 반영한다.
                3) 응답할 때 **항상** 이 키워드를 자연스럽게 대화에 활용한다.
                4) 키워드는 상황(감정/일상)을 파악하고 공감하는 기반으로 사용한다.
                5) 키워드를 중심으로 대화를 확장하며, 사용자가 이야기하고 싶은 방향을 따라간다.
                6) 키워드를 반복 나열하거나 설명하지 않고, **맥락 안에서 자연스럽게 녹여낸다.**
                
                [대화 규칙]
                1) 아래 "대화 기록(JSON)" 은 지금까지의 대화 맥락이다.
                2) 대화 기록은 말투 일관성과 맥락 이해를 위한 참고자료이며, 직접 복사하거나 상세하게 재언급하지 않는다.
                3) "최근 사용자 메시지"에 대해 응답한다.
                4) Assistant 응답만 출력하며 JSON 형식으로 출력하지 않는다.
                5) 모든 규칙과 톤은 절대 깨지지 않는다.
                
                [입력]
                1. 대화 기록:%s
                2. 사용자의 일기 기반 키워드:%s
                3. 최근 사용자 메시지:%s
                위 내용을 기반으로 사용자의 마지막 메시지에 응답하라.
                """.formatted(
//                botScript,
                messageList,
                diarySummaryShort,
                reqMessage
        );

        return summarize(prompt);
    }

    private String objToJson(Object object) {
        try {
            return mapper.writeValueAsString(object);
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize object for OpenAI request payload", e);
            throw OpenAIException.failedToSerialize(object, e);
        }
    }
}
