package me.mmebot.auth.domain;

import jakarta.persistence.*;
import lombok.*;
import me.mmebot.common.persistence.DatabaseNames;
import me.mmebot.user.domain.User;
import org.hibernate.annotations.CreationTimestamp;

import java.time.OffsetDateTime;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Entity
@Table(name = DatabaseNames.Tables.ROLES, schema = DatabaseNames.Schemas.MME_BOT, indexes = {
        @Index(name = "idx_roles_user_id", columnList = "user_id")
})
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "role_id")
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false, length = 32)
    @Enumerated(EnumType.STRING)
    private RoleName roleName;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

}
