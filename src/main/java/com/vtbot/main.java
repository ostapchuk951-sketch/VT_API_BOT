package com.vtbot;

import com.vtbot.config.BotConfig;
import com.vtbot.handler.VTBot;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.telegram.telegrambots.meta.TelegramBotsApi;
import org.telegram.telegrambots.meta.exceptions.TelegramApiException;
import org.telegram.telegrambots.updatesreceivers.DefaultBotSession;

public class Main {
    private static final Logger log = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) {
        log.info("Starting VirusTotal Telegram Bot...");
        BotConfig config = BotConfig.load();

        try {
            TelegramBotsApi botsApi = new TelegramBotsApi(DefaultBotSession.class);
            botsApi.registerBot(new VTBot(config));
            log.info("Bot started successfully: @{}", config.getBotUsername());
        } catch (TelegramApiException e) {
            log.error("Failed to start bot", e);
            System.exit(1);
        }
    }
}
