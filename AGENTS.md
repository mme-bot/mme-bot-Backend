## Global Rules
- Language: Java 25+, Spring Boot 3.5+, JPA (jakarta.persistence).
- Output directories:
    - Entities: src/main/java/me/mmebot/<domain>/domain
    - Repositories: src/main/java/me/mmebot/<domain>/repository
    - sql file(DDL): src/main/resources/database/schema.sql

## Domains
- core: keys, encryption_contexts
- bot: bot, bot_image
- user: users, sns_users
- auth: auth_token, email_verification
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