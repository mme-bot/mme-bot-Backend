# MME Bot 백엔드

MME Bot 백엔드는 Spring Boot 기반의 REST API 서버로, 사용자 인증, 일기/채팅 관리, 암호화 키 관리 등 봇 서비스의 코어 도메인을 제공합니다. 프론트엔드(React)와는 분리되어 있으며 JWT 기반의 인증 흐름과 pgvector 확장을 활용한 임베딩 저장을 지원합니다.

## 기술 스택
- Java 25, Gradle 8 (Gradle Wrapper 포함)
- Spring Boot 3.5 (Web, Data JPA, Security, Validation)
- PostgreSQL 17 + pgvector 확장
- springdoc-openapi 2.8 (Swagger UI 제공)
- Lombok, Nimbus JOSE JWT

## 프로젝트 구조
```
src/main/java/me/mmebot
├─ auth        : 로그인/회원가입, 토큰, 이메일 인증 도메인
├─ bot         : 봇 정보 및 이미지 관리
├─ chat        : 채팅 세션 및 메시지 관리
├─ core        : 암호화 키/컨텍스트, 공통 보안 로직
├─ diary       : 일기 본문, 청크, 임베딩 관리(VectorFloatArrayConverter 사용)
├─ user        : 회원 및 SNS 연동 정보
├─ common      : 공통 설정, 예외, 변환기, 설정 프로퍼티
└─ config      : Spring Security, OpenAPI 설정
```
- 엔티티 스키마는 `me.mmebot.<domain>.domain`, 리포지토리는 `me.mmebot.<domain>.repository`에 위치합니다.
- DDL은 `src/main/resources/database/schema.sql`에 정리되어 있으며, pgvector `vector(1536)` 타입은 `float[]`로 변환됩니다.

## 필수 요구 사항
1. JDK 25 이상
2. Docker & Docker Compose (선택: PostgreSQL/pgvector를 도커로 구동)
3. 로컬 PostgreSQL 17 이상 또는 Docker Compose 기반의 db 서비스
4. `JWT_SECRET_KEY` 등 민감정보는 `.env` 또는 환경 변수로 관리

## 로컬 실행 방법
1. 의존성 다운로드 및 빌드
   ```bash
   ./gradlew clean build
   ```
2. 애플리케이션 실행
   ```bash
   ./gradlew bootRun
   ```
3. 기본 포트는 `8000`이며, API는 `http://localhost:8000/api/v1` 아래에서 제공됩니다.
4. 종료는 `Ctrl + C`로 수행합니다.

## Docker Compose 사용
```bash
docker compose up --build
```
- `docker-compose.yml`은 애플리케이션(`app`)과 PostgreSQL + pgvector(`db`)를 함께 올립니다.
- `.env` 파일을 만들어 `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `DATASOURCE_URL`, `JWT_SECRET_KEY` 등을 정의하세요.
- DB 초기화가 끝나면 애플리케이션 컨테이너가 자동으로 기동됩니다.

## 데이터베이스 준비
- `schema.sql`로 전체 스키마를 재생성할 수 있습니다.
- pgvector 확장을 위해 데이터베이스에서 `CREATE EXTENSION IF NOT EXISTS vector;` 명령이 필요합니다.
- 로컬 개발 시에는 `docker-compose.yml`의 `db` 서비스가 자동으로 확장을 설치합니다.

## 환경 설정
- 기본 설정 파일: `src/main/resources/application.yml`
  - `spring.datasource.*`: 데이터베이스 접속 정보
  - `api.base-path`: API 베이스 경로(`/api/v1`)
  - `external.frontend-url`: CORS 허용 대상(React 웹 앱 주소)
  - `jwt.*`: JWT 키 ID, 발급자, 만료 시간 설정
- 배포 환경에서는 환경 변수 또는 추가 `application-*.yml`로 값을 재정의하세요.

## 인증 및 보안
- BCryptPasswordEncoder를 사용하여 비밀번호를 해시합니다.
- Access Token은 JWT, Refresh Token은 DB(`auth_token` 테이블)에 저장됩니다.
- Access Token은 HttpOnly + Secure 쿠키로 내려주며, 보호 API는 `Authorization: Bearer <token>` 헤더를 요구합니다.
- JWT에는 `roles.role_name`, `users.user_id` 정보가 포함됩니다.
- 인증 실패 시 401, 권한 부족 시 403 응답을 반환합니다.

## API 문서
현재 배포 상태이므로 로컬이 아닌 배포 주소를 활용합니다.
- Swagger UI: [http://mmebot.me:5000/swagger-ui](http://mmebot.me:5000/swagger-ui)
- OpenAPI JSON: [http://mmebot.me:5000/api/v1/api-docs](http://mmebot.me:5000/api/v1/api-docs)
- `OpenApiConfiguration`에서 공통 에러 응답, 보안 스킴, 서버 정보가 자동 등록됩니다.

## 테스트
```bash
./gradlew test
```
- Spring Security 테스트 유틸과 JUnit Platform을 사용합니다.

## 추가 참고 사항
- CORS는 설정된 웹 프론트엔드 도메인만 허용하며, `GET/POST/PUT/PATCH/OPTIONS` 메서드를 지원합니다.
- `ExternalServiceProperties`, `JwtProperties`, `ApiProp`는 `@ConfigurationProperties`로 주입됩니다.
- 암호화 키/컨텍스트(`core` 도메인)는 일기/채팅 등 민감 데이터 접근을 위한 기반 정보입니다.
- `VectorFloatArrayConverter`는 pgvector 임베딩을 `float[]`로 변환하여 저장/조회합니다.
