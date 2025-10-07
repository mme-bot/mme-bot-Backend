## Global Rules
- Language: Java 25+, Spring Boot 3.5+, JPA (jakarta.persistence).
- Output directories:
    - Entities: src/main/java/me/mmebot/<domain>/domain
    - Repositories: src/main/java/me/mmebot/<domain>/repository
    - sql file(DDL): src/main/resources/database/schema.sql
    - config file: src/main/resources/application.yml

## Domains
- core: keys, encryption_contexts
- bot: bot, bot_image
- user: users, sns_users
- auth: role, auth_token, email_verification
- diary: diary, diary_chunk, diary_chunk_embedding
- chat: chat_session, chat_message

## Type Mapping
- TIMESTAMPTZ -> java.time.OffsetDateTime consistently.
- vector(1536) -> float[] using a JPA AttributeConverter (see VectorFloatArrayConverter).
- BYTEA -> byte[].
- VARCHAR/TEXT -> String.
- DATE -> java.time.LocalDate.
- BOOLEAN/INT/BIGINT -> Java primitives where safe.
- vector(1536) -> float[] using a JPA AttributeConverter (create VectorFloatArrayConverter in me.mmebot.diary.domain, and annotate the embedding field with @Convert(converter = VectorFloatArrayConverter.class))

## pgvector
- Provide a reusable AttributeConverter:
    - `@Converter(autoApply = false) public class VectorFloatArrayConverter implements AttributeConverter<float[], Object> { ... }`
    - Persist as JDBC `Array` (float8) or String form, whichever is simpler for PostgreSQL driver.
    - Use on diary_chunk_embedding.embedding.

## API
모든 DTO 에는 database table 을 기준으로 `@Vaild` 설정 필수
### auth
- `signIn`
  - req: email, passwd
  - res: userId, botId, nickname, accessToken, refreshToken (JWT)
    - 403 code : deletedAt 이 null이 아닐 경우 탈퇴한 회원
    - 404 code : email 또는 passwd 가 다를 경우
- `signUp`
  - req: email, passwd, nickname, emailVerificationId
  - res: none
    - 403 code : emailVerificationId 에서 isVerified -> false 일 때
- `sendEmailVerification`
  - req: email
  - res: emailVerificationId, code
    - expiredAt 은 sendAt 5분 후로 설정
    - 404 code : email 형식이 다를 때
    - 429 code : EmailVerification 에서 sendAt 으로 비교하여 10개 이상 전송됐을 경우.
- `checkEmailVerification`
  - req: emailVerificationId, code
  - res: none
    - 400 code : code 값이 다를 경우
    - 404 code : emailVerificationId 값이 유효하지 않을 때
    - 410 code : expiredAt 값이 현재 시간 이후일 경우 
- `TokenReissue`
  - req: userId, refreshToken
  - res: accessToken, refreshToken
    - 404 code : userId 값이 유효하지 않을 때
    - 400 code : refreshToken 이 유효하지 않을 때

## Repository
- Generate Spring Data JPA repositories per domain.
- Use Optional<T> and derived query methods for common lookups.

## JPA Entity Generation Rules
- Package: `me.mmebot`
   - domain List: `user`, `diary`, `auth`, `chat`
   - `user` Entity: 
- Jakarta Persistence 3.x (import `jakarta.persistence.*`)
- Lombok: `@Getter`, `@NoArgsConstructor`, `@AllArgsConstructor`, `@Builder`
- snake_case → camelCase
- FK는 `@ManyToOne(fetch = LAZY)` 기본, 양방향은 지양하고 필요 시 명시
- PK는 `@Id` + `@GeneratedValue(strategy = GenerationType.IDENTITY)` (필요 시 바꿔줘)
- DDL의 INDEX/UNIQUE는 `@Table(indexes = ...)`, `@Column(unique = true)`로 반영
- ENUM은 `@Enumerated(EnumType.STRING)`
- 생성/수정 시간은 `@CreationTimestamp`, `@UpdateTimestamp`
- Entity 의 Schema name, Table name 은 enum 으로 관리

## Spring Security Rules
- React 로 만들어진 WebServer 서버가 따로 있으며 Spring 은 RestApi 서버로 이용한다. 웹 서버의 주소는 config file로 관리한다.
- Cors 설정은 Webserver 만 허용하고, `GET`, `POST`, `PUT`, `PATCH`, `OPTIONS` 메서드를 허용한다.
- passwordEncoder 는 BcryptEncoder 를 이용한다.
- JWT 방식을 이용해 인증한다. `auth_token` 객체를 이용하며, JWT 관련 설정은 config file 로 관리한다.
  - JWT 에 들어갈 정보: `roles.role_name`, `users.user_id`
  - refresh 토큰은 DB에 저장한다.
  - access token 은 쿠키에 담아 응답한다. 인증이 필요할 땐 `Authorization` 헤더에 `Bearer token...` 형식으로 요청이 들어온다.
    - 쿠키 설정: HttpOnly+Secure (SameSite=Lax 권장, cross-site면 None + HTTPS)
  - JWS, JWE 를 사용.
  - 암호화, 복호화 클래스를 분리한다.
- 401 code: Access token 인증이 실패할 경우 (refresh token 으로 재인증 필요)