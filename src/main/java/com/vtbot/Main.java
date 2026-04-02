package com.vtbot;

import com.vtbot.config.BotConfig;
import com.vtbot.handler.VTBot;
import com.sun.net.httpserver.HttpServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.telegram.telegrambots.meta.TelegramBotsApi;
import org.telegram.telegrambots.meta.exceptions.TelegramApiException;
import org.telegram.telegrambots.updatesreceivers.DefaultBotSession;

import java.io.IOException;
import java.net.InetSocketAddress;

public class Main {
    private static final Logger log = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) {
        log.info("Starting VirusTotal Telegram Bot...");

        // Health check HTTP server so Render (free web service) doesn't kill the process
        startHealthServer();

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

    private static void startHealthServer() {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "10000"));
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
            server.createContext("/", exchange -> {
                byte[] response = "OK".getBytes();
                exchange.sendResponseHeaders(200, response.length);
                exchange.getResponseBody().write(response);
                exchange.getResponseBody().close();
            });
            server.start();
            log.info("Health check server started on port {}", port);
        } catch (IOException e) {
            log.warn("Could not start health server: {}", e.getMessage());
        }
    }
}
