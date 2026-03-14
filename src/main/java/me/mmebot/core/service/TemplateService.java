package me.mmebot.core.service;

import com.samskivert.mustache.Mustache;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class TemplateService {

    private final ResourceLoader resourceLoader;
    private final Mustache.Compiler mustacheCompiler;
    private final String TEMPLATE_LOCATION = "classpath:templates/";

    public String generatePrompt(String templateName, Map<String, Object> data) {
        // 2. 데이터 매핑 및 렌더링
        try (InputStreamReader reader = getResource("prompt", templateName)) {
            return mustacheCompiler.compile(reader).execute(data);
        } catch (IOException e) {
            throw new RuntimeException("템플릿 렌더링 실패: " + templateName, e);
        }
    }

    private InputStreamReader getResource(String dirName, String templateName) {
        try {
            // 1. templates 폴더에서 파일 읽기
            Resource resource = resourceLoader.getResource(TEMPLATE_LOCATION + dirName + "/" + templateName);
            return new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            // 사용자 정의 예외
            throw new RuntimeException("템플릿을 읽을 수 없습니다: " + templateName, e);
        }
    }
}
