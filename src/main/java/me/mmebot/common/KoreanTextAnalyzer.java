package me.mmebot.common;

import org.openkoreantext.processor.KoreanTokenJava;
import org.openkoreantext.processor.OpenKoreanTextProcessorJava;
import org.springframework.stereotype.Service;
import scala.collection.Seq;

import java.util.List;
import java.util.Set;

import static org.openkoreantext.processor.tokenizer.KoreanTokenizer.*;

@Service
public class KoreanTextAnalyzer {

    // TODO: 나중에 DB 로 관리해야할 것 같지만 일단 빠른 개발을 위해 1차로는 코드에 명시하도록 함.
    private static final Set<String> DIARY_STOPWORDS = Set.of(
            "오늘", "어제", "내일", "지금", "방금", "여기", "저기", "그곳", "곳",
            "나", "내", "우리", "너", "그", "그녀", "자기", "니", "본인",
            "정말", "진짜", "너무", "되게", "조금", "약간", "매우",
            "그리고", "그런데", "그래서", "하지만", "그럼", "근데", "그냥", "또",
            "하다", "되다", "아니다", "있다", "없다", "같다",
            "아침", "점심", "저녁", "오늘밤", "밤"
    );

    public List<String> extractKeywords(String text) {
        CharSequence normalized = OpenKoreanTextProcessorJava.normalize(text);
        Seq<KoreanToken> tokens = OpenKoreanTextProcessorJava.tokenize(normalized);
        List<KoreanTokenJava> tokenList = OpenKoreanTextProcessorJava
                .tokensToJavaKoreanTokenList(tokens);

        return tokenList.stream()
                .filter(t -> t.getPos().toString().equals("Noun")
                        || t.getPos().toString().equals("Adjective"))
                .map(KoreanTokenJava::getText)
                .filter(w -> !DIARY_STOPWORDS.contains(w) && w.length() > 1)
                .distinct()
                .toList();
    }
}
