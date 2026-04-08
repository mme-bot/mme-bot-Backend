package me.mmebot;

import me.mmebot.common.config.TestOpenAIConfig;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

@SpringBootTest
@Import(TestOpenAIConfig.class)
class MmebotApplicationTests {

	@Test
	void contextLoads() {
	}

}
