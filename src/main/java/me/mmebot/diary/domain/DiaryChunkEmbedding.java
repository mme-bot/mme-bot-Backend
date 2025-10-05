package me.mmebot.diary.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import me.mmebot.common.converter.VectorFloatArrayConverter;
import me.mmebot.common.persistence.DatabaseNames;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Entity
@Table(name = DatabaseNames.Tables.DIARY_CHUNK_EMBEDDING, schema = DatabaseNames.Schemas.MME_BOT)
public class DiaryChunkEmbedding {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "diary_chunk_embedding_id")
    private Long id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "diary_chunk_id", nullable = false, unique = true)
    private DiaryChunk diaryChunk;

    @Convert(converter = VectorFloatArrayConverter.class)
    @Column(nullable = false, columnDefinition = "vector(1536)")
    private float[] embedding;
}
