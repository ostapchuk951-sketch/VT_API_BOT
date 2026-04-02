package com.vtbot.handler;

import com.vtbot.config.BotConfig;
import com.vtbot.model.ScanResult;
import com.vtbot.service.MessageFormatter;
import com.vtbot.service.VirusTotalService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.telegram.telegrambots.bots.TelegramLongPollingBot;
import org.telegram.telegrambots.meta.api.methods.GetFile;
import org.telegram.telegrambots.meta.api.methods.ParseMode;
import org.telegram.telegrambots.meta.api.methods.send.SendMessage;
import org.telegram.telegrambots.meta.api.methods.updatingmessages.EditMessageText;
import org.telegram.telegrambots.meta.api.objects.*;
import org.telegram.telegrambots.meta.exceptions.TelegramApiException;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class VTBot extends TelegramLongPollingBot {
    private static final Logger log = LoggerFactory.getLogger(VTBot.class);

    // Regex patterns for hash types
    private static final String SHA256_PATTERN = "[a-fA-F0-9]{64}";
    private static final String SHA1_PATTERN   = "[a-fA-F0-9]{40}";
    private static final String MD5_PATTERN    = "[a-fA-F0-9]{32}";

    private final BotConfig config;
    private final VirusTotalService vtService;
    private final ExecutorService executor;

    public VTBot(BotConfig config) {
        super(config.getBotToken());
        this.config = config;
        this.vtService = new VirusTotalService(config.getVirusTotalApiKey());
        this.executor = Executors.newCachedThreadPool();
    }

    @Override
    public String getBotUsername() {
        return config.getBotUsername();
    }

    @Override
    public void onUpdateReceived(Update update) {
        if (!update.hasMessage()) return;
        Message msg = update.getMessage();

        if (msg.hasDocument()) {
            handleDocument(msg);
        } else if (msg.hasText()) {
            handleText(msg);
        }
    }

    // ─── Document handling ────────────────────────────────────────────────────

    private void handleDocument(Message msg) {
        Document doc = msg.getDocument();
        long chatId = msg.getChatId();
        String fileName = doc.getFileName() != null ? doc.getFileName() : "unknown";
        long fileSize = doc.getFileSize() != null ? doc.getFileSize() : 0;

        if (fileSize > config.getMaxFileSizeBytes()) {
            sendHtml(chatId, MessageFormatter.formatError(
                    "Файл завеликий. Максимум: " + (config.getMaxFileSizeBytes() / 1024 / 1024) + " МБ"));
            return;
        }

        // Send "waiting" message and remember its ID for editing
        Integer waitMsgId = sendHtmlAndGetId(chatId, MessageFormatter.formatWaiting(fileName));

        executor.submit(() -> {
            Path tempDir = null;
            try {
                tempDir = Files.createTempDirectory("vtbot_");
                File downloaded = downloadTelegramFile(doc.getFileId(), tempDir, fileName);

                ScanResult result = vtService.scanFile(downloaded, fileName);
                editOrSend(chatId, waitMsgId, MessageFormatter.formatResult(result));

            } catch (Exception e) {
                log.error("Scan failed for file {}", fileName, e);
                editOrSend(chatId, waitMsgId, MessageFormatter.formatError(
                        "Не вдалося просканувати файл: " + e.getMessage()));
            } finally {
                if (tempDir != null) {
                    deleteDirectory(tempDir.toFile());
                }
            }
        });
    }

    // ─── Text / command handling ──────────────────────────────────────────────

    private void handleText(Message msg) {
        String text = msg.getText().trim();
        long chatId = msg.getChatId();

        if (text.startsWith("/start")) {
            sendHtml(chatId, """
                    👋 <b>Привіт!</b> Я перевіряю файли через <b>VirusTotal</b>.
                    
                    Надішли мені будь-який файл або хеш (MD5/SHA1/SHA256) і я скажу, чи він небезпечний.
                    
                    /help — детальніша довідка
                    """);
            return;
        }

        if (text.startsWith("/help")) {
            sendHtml(chatId, MessageFormatter.formatHelp());
            return;
        }

        // /scan <hash> or just a bare hash
        String hash = null;
        if (text.startsWith("/scan ")) {
            hash = text.substring(6).trim();
        } else if (text.matches(SHA256_PATTERN) || text.matches(SHA1_PATTERN) || text.matches(MD5_PATTERN)) {
            hash = text;
        }

        if (hash != null) {
            final String finalHash = hash;
            Integer waitId = sendHtmlAndGetId(chatId, "⏳ Шукаю хеш <code>" + finalHash + "</code> у базі VirusTotal...");
            executor.submit(() -> {
                try {
                    ScanResult result = vtService.scanHash(finalHash);
                    if (result == null) {
                        editOrSend(chatId, waitId,
                                "❓ <b>Не знайдено.</b>\nЦей хеш відсутній у базі VirusTotal.\nСпробуй завантажити файл напряму.");
                    } else {
                        editOrSend(chatId, waitId, MessageFormatter.formatResult(result));
                    }
                } catch (Exception e) {
                    log.error("Hash scan failed: {}", finalHash, e);
                    editOrSend(chatId, waitId, MessageFormatter.formatError("Помилка при пошуку: " + e.getMessage()));
                }
            });
            return;
        }

        // Unknown input
        sendHtml(chatId, "ℹ️ Надішли файл або команду /help для довідки.");
    }

    // ─── Telegram file download ───────────────────────────────────────────────

    private File downloadTelegramFile(String fileId, Path dir, String fileName) throws TelegramApiException, IOException {
        GetFile getFile = new GetFile(fileId);
        org.telegram.telegrambots.meta.api.objects.File tgFile = execute(getFile);

        // Sanitize filename
        String safeName = fileName.replaceAll("[^a-zA-Z0-9._\\-]", "_");
        File dest = dir.resolve(safeName).toFile();
        downloadFile(tgFile, dest);
        return dest;
    }

    // ─── Messaging helpers ────────────────────────────────────────────────────

    private void sendHtml(long chatId, String text) {
        SendMessage msg = SendMessage.builder()
                .chatId(chatId)
                .text(text)
                .parseMode(ParseMode.HTML)
                .disableWebPagePreview(true)
                .build();
        try {
            execute(msg);
        } catch (TelegramApiException e) {
            log.error("Failed to send message to {}", chatId, e);
        }
    }

    private Integer sendHtmlAndGetId(long chatId, String text) {
        SendMessage msg = SendMessage.builder()
                .chatId(chatId)
                .text(text)
                .parseMode(ParseMode.HTML)
                .disableWebPagePreview(true)
                .build();
        try {
            Message sent = execute(msg);
            return sent.getMessageId();
        } catch (TelegramApiException e) {
            log.error("Failed to send message", e);
            return null;
        }
    }

    private void editOrSend(long chatId, Integer messageId, String text) {
        if (messageId != null) {
            EditMessageText edit = EditMessageText.builder()
                    .chatId(chatId)
                    .messageId(messageId)
                    .text(text)
                    .parseMode(ParseMode.HTML)
                    .disableWebPagePreview(true)
                    .build();
            try {
                execute(edit);
                return;
            } catch (TelegramApiException e) {
                log.warn("Could not edit message {}, sending new one", messageId);
            }
        }
        sendHtml(chatId, text);
    }

    // ─── Utils ────────────────────────────────────────────────────────────────

    private void deleteDirectory(File dir) {
        if (dir == null) return;
        File[] files = dir.listFiles();
        if (files != null) for (File f : files) f.delete();
        dir.delete();
    }
}
