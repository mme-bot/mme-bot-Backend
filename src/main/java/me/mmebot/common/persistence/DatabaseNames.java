package me.mmebot.common.persistence;

public final class DatabaseNames {

    private DatabaseNames() {
    }

    public static final class Schemas {

        public static final String MME_BOT = "mmebot";

        private Schemas() {
        }
    }

    public static final class Tables {

        public static final String AUTH_TOKEN = "auth_token";
        public static final String BOT = "bot";
        public static final String BOT_IMAGE = "bot_image";
        public static final String CHAT_MESSAGE = "chat_message";
        public static final String CHAT_SESSION = "chat_session";
        public static final String DIARY = "diary";
        public static final String DIARY_CHUNK = "diary_chunk";
        public static final String DIARY_CHUNK_EMBEDDING = "diary_chunk_embedding";
        public static final String EMAIL_VERIFICATION = "email_verification";
        public static final String ENCRYPTION_CONTEXTS = "encryption_contexts";
        public static final String KEYS = "keys";
        public static final String PROVIDER_TOKENS = "provider_tokens";
        public static final String SNS_USERS = "sns_users";
        public static final String USERS = "users";
        public static final String ROLES = "roles";

        private Tables() {
        }
    }
}
