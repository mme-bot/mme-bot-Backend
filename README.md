# MME Bot 백엔드

MME Bot 백엔드는 일기 기반 감정 케어 봇을 위한 Spring Boot REST API입니다. 사용자 인증, 일기/채팅 관리, 암호화 키 관리, 이메일 인증, OpenAI 연동을 단일 서버에서 제공하며 React 웹 애플리케이션과 분리된 백엔드로 동작합니다.

## 데모 영상

https://github.com/user-attachments/assets/e5136d75-1ded-452d-a72e-eb8fe3833e55



## 관련 문서
[http://mmebot.me:8000/swagger-ui/index.html](http://mmebot.me:8000/swagger-ui/index.html)

[노션 페이지](https://hyuil.notion.site/1-1-2-2dfcdcc9ff5080658a4bd7ac6cd1a0bb?source=copy_link)

## 기술 스택
- Java 25 + Gradle 8 Wrapper, Spring Boot 3.5 (Web, Data JPA, Security, Validation, Mail, Redis, AOP)
- PostgreSQL 17 + pgvector, Redis 7.4, Docker Compose 지원
- SpringDoc OpenAPI 2.8.x, Lombok, Nimbus JOSE JWT, Google Mail API, open-korean-text, OpenAI Java SDK 4.8.0

## 프로젝트 구조
```
src/main/java/me/mmebot
├─ auth        : 회원/토큰/이메일 인증, JWT(JWS+JWE), Redis 토큰 캐시
├─ bot         : 봇 프로필 및 이미지 관리, 기본 조회 API
├─ chat        : 일기 기반 채팅 세션/메시지, OpenAI 연동
├─ core        : 암호화 키/컨텍스트, AES-GCM 유틸리티
├─ diary       : 일기·청크·임베딩(VectorFloatArrayConverter) 관리
├─ openai      : GPT 호출, 한국어 형태소 기반 요약
├─ user        : 사용자·SNS 연동, 테스트용 API
├─ common      : 설정, 예외, 암호화, 컨버터, 메일, Validator
└─ config      : SecurityFilterChain, OpenAPI 커스터마이저
```
- 엔티티는 `me.mmebot.<domain>.domain`, 리포지토리는 `me.mmebot.<domain>.repository`에 배치되며 `DatabaseNames`가 스키마/테이블 상수를 제공합니다.
- `DiaryChunkEmbedding`은 `VectorFloatArrayConverter`로 pgvector `vector(1536)` ↔ `float[]` 변환을 수행합니다.
- 전체 테이블 정의는 `src/main/resources/database/schema.sql`에서 확인할 수 있습니다.

## 필수 요구 사항
1. JDK 25 이상 & Gradle Wrapper
2. PostgreSQL 17 + `CREATE EXTENSION vector` (또는 `docker-compose.yml`의 pgvector 이미지)

## 로컬 실행 방법
1. PostgreSQL/Redis를 실행하고 `schema.sql`로 초기화하거나 `SPRING_PROFILES_ACTIVE=dev`로 내장 설정을 사용합니다.
2. 의존성 설치 및 빌드
   ```bash
   ./gradlew clean build
   ```
3. 애플리케이션 실행 (기본 포트 8000, API Base `/api/v1`)
   ```bash
   APP_PORT=8000 SPRING_PROFILES_ACTIVE=dev ./gradlew bootRun
   ```
4. 종료는 `Ctrl + C`로 수행합니다.

## Docker Compose 사용
```bash
docker compose up --build
```
- `app`, `db(pgvector)` 컨테이너가 함께 기동하며 `.env`에 포트/DB/JWT/AES/OpenAI/Gmail 값을 정의합니다.
- Compose는 DB 초기화와 Redis 준비 후 애플리케이션을 자동으로 시작합니다.

## 데이터베이스 준비
- `schema.sql`은 `keys`, `encryption_contexts`, `users`, `sns_users`, `auth_token`, `email_verification`, `diary`, `diary_chunk`, `diary_chunk_embedding`, `chat_session`, `chat_message`, `roles`, `bot`, `bot_image`, `provider_tokens` 등을 생성합니다.
- 초기 기동 시 `DefaultUserInitializer`가 카키/몽몽/채드 봇과 관리자 계정을 삽입해 빠르게 기능을 체험할 수 있습니다.

## 환경 설정
- 기본 설정(`application.yml`)은 `server.port`, `spring.datasource`, `spring.mail`, `email`, `google`, `key`, `crypto.aes256-gcm`, `jwt`, `api.base-path` 등을 환경 변수로 주입받습니다.
- `application-dev.yml`은 로컬 DB/Redis, Swagger 경로, CORS 도메인을, `application-prod.yml`은 배포용 포트/호스트 설정을 제공합니다.
- `ExternalServiceProperties`와 `ApiProp`을 통해 CORS 허용 도메인과 OpenAPI server 정보를 중앙에서 관리합니다.

## 인증 및 보안
- 양방향 암호화 알고리즘으로 `AES256-GCM` 을 사용하고 aad 값으로 검증합니다.
- .env 파일을 분리하여 OS 환경 변수로 주입합니다.

## API 문서
- SpringDoc이 자동 스캔하며 `OpenApiConfiguration`이 공통 응답/보안 스키마를 추가합니다.
- 로컬 실행 후 Swagger UI는 `http://localhost:8000/swagger-ui`, OpenAPI JSON은 `/api/v1/api-docs`에서 확인합니다.

## 테스트
```bash
./gradlew test
```
- JUnit 5와 `spring-security-test`를 사용하며 프로파일별 DB/Redis 설정을 그대로 활용합니다.

## 추가 참고 사항
- `ChatService`는 일기 요약, 봇 페르소나, 기존 채팅 로그를 GPT-4.1-mini 모델에 전달하고 결과를 AES-GCM으로 저장합니다.
- `KoreanTextAnalyzer`가 open-korean-text로 추출한 키워드를 `OpenAIService` 프롬프트에 활용합니다.
