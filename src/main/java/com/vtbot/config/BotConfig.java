package com.vtbot.config;

import io.github.cdimascio.dotenv.Dotenv;
import io.github.cdimascio.dotenv.DotenvException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BotConfig {
    private static final Logger log = LoggerFactory.getLogger(BotConfig.class);

    private final String botToken;
    private final String botUsername;
    private final String virusTotalApiKey;
    private final long maxFileSizeBytes;

    private BotConfig(String botToken, String botUsername, String virusTotalApiKey, long maxFileSizeBytes) {
        this.botToken = botToken;
        this.botUsername = botUsername;
        this.virusTotalApiKey = virusTotalApiKey;
        this.maxFileSizeBytes = maxFileSizeBytes;
    }

    public static BotConfig load() {
        Dotenv dotenv;
        try {
            dotenv = Dotenv.configure().ignoreIfMissing().load();
        } catch (DotenvException e) {
            log.warn("Could not load .env file, using system environment variables");
            dotenv = Dotenv.configure().ignoreIfMissing().load();
        }

        String botToken = getRequired(dotenv, "BOT_TOKEN");
        String botUsername = getRequired(dotenv, "BOT_USERNAME");
        String vtApiKey = getRequired(dotenv, "VIRUSTOTAL_API_KEY");
        long maxSize = Long.parseLong(getOrDefault(dotenv, "MAX_FILE_SIZE_MB", "32")) * 1024 * 1024;

        log.info("Configuration loaded. Max file size: {} MB", maxSize / 1024 / 1024);
        return new BotConfig(botToken, botUsername, vtApiKey, maxSize);
    }

    private static String getRequired(Dotenv dotenv, String key) {
        String value = dotenv.get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Required environment variable not set: " + key);
        }
        return value;
    }

    private static String getOrDefault(Dotenv dotenv, String key, String defaultValue) {
        String value = dotenv.get(key);
        return (value != null && !value.isBlank()) ? value : defaultValue;
    }

    public String getBotToken() { return botToken; }
    public String getBotUsername() { return botUsername; }
    public String getVirusTotalApiKey() { return virusTotalApiKey; }
    public long getMaxFileSizeBytes() { return maxFileSizeBytes; }
}
