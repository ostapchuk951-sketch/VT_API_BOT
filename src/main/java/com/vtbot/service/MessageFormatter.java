package com.vtbot.service;

import com.vtbot.model.ScanResult;

import java.util.Map;

public class MessageFormatter {

    private static final int MAX_DETECTIONS_SHOWN = 20;

    public static String formatResult(ScanResult result) {
        StringBuilder sb = new StringBuilder();

        // Verdict header
        String verdictEmoji = switch (result.getVerdict()) {
            case CLEAN -> "✅";
            case SUSPICIOUS -> "⚠️";
            case MALICIOUS -> "🚨";
        };
        String verdictText = switch (result.getVerdict()) {
            case CLEAN -> "ЧИСТО";
            case SUSPICIOUS -> "ПІДОЗРІЛИЙ";
            case MALICIOUS -> "ШКІДЛИВИЙ";
        };

        sb.append(verdictEmoji).append(" <b>").append(verdictText).append("</b>\n\n");

        // File info
        sb.append("📄 <b>Файл:</b> ").append(escapeHtml(result.getFileName())).append("\n");
        if (result.getSha256() != null) {
            sb.append("🔑 <b>SHA256:</b> <code>").append(result.getSha256()).append("</code>\n");
        }
        sb.append("\n");

        // Detection stats
        sb.append("📊 <b>Результати сканування:</b>\n");
        sb.append("├ 🔴 Шкідливих: <b>").append(result.getMalicious()).append("</b>\n");
        sb.append("├ 🟡 Підозрілих: <b>").append(result.getSuspicious()).append("</b>\n");
        sb.append("└ 🟢 Чистих: <b>")
                .append(result.getUndetected())
                .append("</b> / <b>")
                .append(result.getTotalEngines())
                .append("</b> двигунів\n\n");

        // Detection list
        Map<String, ScanResult.EngineResult> detections = result.getDetections();
        if (!detections.isEmpty()) {
            sb.append("🔍 <b>Виявлення (").append(detections.size()).append("):</b>\n");
            int shown = 0;
            for (Map.Entry<String, ScanResult.EngineResult> entry : detections.entrySet()) {
                if (shown >= MAX_DETECTIONS_SHOWN) {
                    sb.append("  <i>... та ще ").append(detections.size() - shown).append(" виявлень</i>\n");
                    break;
                }
                String emoji = "malicious".equals(entry.getValue().category()) ? "🔴" : "🟡";
                String detResult = entry.getValue().result() != null
                        ? escapeHtml(entry.getValue().result())
                        : "Generic";
                sb.append(emoji).append(" <code>").append(escapeHtml(entry.getKey()))
                        .append("</code>: ").append(detResult).append("\n");
                shown++;
            }
            sb.append("\n");
        }

        // VT link
        sb.append("🔗 <a href=\"").append(result.getVtLink()).append("\">Відкрити на VirusTotal</a>");

        return sb.toString();
    }

    public static String formatWaiting(String fileName) {
        return "⏳ Завантажую <b>" + escapeHtml(fileName) + "</b> на VirusTotal...\n" +
               "<i>Це може зайняти до 2 хвилин. Будь ласка, зачекайте.</i>";
    }

    public static String formatError(String reason) {
        return "❌ <b>Помилка:</b> " + escapeHtml(reason);
    }

    public static String formatHelp() {
        return """
                🛡️ <b>VirusTotal Scanner Bot</b>
                
                Надішли файл (до 32 МБ) або хеш файлу — бот перевірить його через VirusTotal.
                
                <b>Команди:</b>
                /start — привітання
                /help — ця довідка
                /scan &lt;hash&gt; — перевірити за SHA256/MD5/SHA1
                
                <b>Підтримувані формати:</b>
                Будь-які файли до 32 МБ
                
                <b>Інтерпретація результатів:</b>
                ✅ 0 виявлень — файл чистий
                ⚠️ 1–4 виявлення — підозрілий
                🚨 5+ виявлень — шкідливий
                """;
    }

    private static String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;");
    }
}
