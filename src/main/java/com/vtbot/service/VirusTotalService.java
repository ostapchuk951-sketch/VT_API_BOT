package com.vtbot.service;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.vtbot.model.ScanResult;
import okhttp3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class VirusTotalService {
    private static final Logger log = LoggerFactory.getLogger(VirusTotalService.class);

    private static final String VT_BASE = "https://www.virustotal.com/api/v3";
    private static final int POLL_INTERVAL_MS = 5000;
    private static final int MAX_POLLS = 60; // 2 minutes max

    private final String apiKey;
    private final OkHttpClient http;

    public VirusTotalService(String apiKey) {
        this.apiKey = apiKey;
        this.http = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(60, TimeUnit.SECONDS)
                .writeTimeout(60, TimeUnit.SECONDS)
                .build();
    }

    /**
     * Upload file and wait for analysis result.
     */
    public ScanResult scanFile(File file, String originalName) throws IOException, InterruptedException {
        log.info("Uploading file: {} ({} bytes)", originalName, file.length());

        // Step 1: Upload file
        String analysisId = uploadFile(file, originalName);
        log.info("Analysis ID: {}", analysisId);

        // Step 2: Poll until done
        JsonObject attributes = pollAnalysis(analysisId);

        // Step 3: Get full file report by sha256
        String sha256 = attributes.getAsJsonObject("stats") != null
                ? extractSha256FromAnalysis(attributes)
                : null;

        return buildResult(originalName, sha256, attributes);
    }

    /**
     * Scan by SHA256 hash (check if already known to VT).
     */
    public ScanResult scanHash(String sha256) throws IOException {
        Request request = new Request.Builder()
                .url(VT_BASE + "/files/" + sha256)
                .addHeader("x-apikey", apiKey)
                .get()
                .build();

        try (Response response = http.newCall(request).execute()) {
            if (response.code() == 404) return null;
            String body = requireBody(response);
            JsonObject root = JsonParser.parseString(body).getAsJsonObject();
            JsonObject attributes = root.getAsJsonObject("data").getAsJsonObject("attributes");
            return buildResult("unknown", sha256, attributes);
        }
    }

    // ─── Private helpers ─────────────────────────────────────────────────────

    private String uploadFile(File file, String originalName) throws IOException {
        // Use large file endpoint for files > 32 MB
        String uploadUrl;
        if (file.length() > 32 * 1024 * 1024) {
            uploadUrl = getLargeFileUploadUrl();
        } else {
            uploadUrl = VT_BASE + "/files";
        }

        RequestBody requestBody = new MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart("file", originalName,
                        RequestBody.create(file, MediaType.parse("application/octet-stream")))
                .build();

        Request request = new Request.Builder()
                .url(uploadUrl)
                .addHeader("x-apikey", apiKey)
                .post(requestBody)
                .build();

        try (Response response = http.newCall(request).execute()) {
            String body = requireBody(response);
            JsonObject root = JsonParser.parseString(body).getAsJsonObject();
            return root.getAsJsonObject("data").get("id").getAsString();
        }
    }

    private String getLargeFileUploadUrl() throws IOException {
        Request request = new Request.Builder()
                .url(VT_BASE + "/files/upload_url")
                .addHeader("x-apikey", apiKey)
                .get()
                .build();

        try (Response response = http.newCall(request).execute()) {
            String body = requireBody(response);
            JsonObject root = JsonParser.parseString(body).getAsJsonObject();
            return root.get("data").getAsString();
        }
    }

    private JsonObject pollAnalysis(String analysisId) throws IOException, InterruptedException {
        String url = VT_BASE + "/analyses/" + analysisId;

        for (int i = 0; i < MAX_POLLS; i++) {
            Thread.sleep(POLL_INTERVAL_MS);

            Request request = new Request.Builder()
                    .url(url)
                    .addHeader("x-apikey", apiKey)
                    .get()
                    .build();

            try (Response response = http.newCall(request).execute()) {
                String body = requireBody(response);
                JsonObject root = JsonParser.parseString(body).getAsJsonObject();
                JsonObject attributes = root.getAsJsonObject("data").getAsJsonObject("attributes");
                String status = attributes.get("status").getAsString();

                log.debug("Poll {}/{} - status: {}", i + 1, MAX_POLLS, status);

                if ("completed".equals(status)) {
                    return attributes;
                }
            }
        }
        throw new IOException("Analysis timed out after " + (MAX_POLLS * POLL_INTERVAL_MS / 1000) + " seconds");
    }

    private String extractSha256FromAnalysis(JsonObject attributes) {
        try {
            JsonObject meta = attributes.getAsJsonObject("meta");
            if (meta != null && meta.has("file_info")) {
                return meta.getAsJsonObject("file_info").get("sha256").getAsString();
            }
        } catch (Exception ignored) {}
        return null;
    }

    private ScanResult buildResult(String fileName, String sha256, JsonObject attributes) {
        JsonObject stats = attributes.getAsJsonObject("stats");
        int malicious = stats.get("malicious").getAsInt();
        int suspicious = stats.get("suspicious").getAsInt();
        int undetected = stats.get("undetected").getAsInt();
        int harmless = stats.has("harmless") ? stats.get("harmless").getAsInt() : 0;
        int total = malicious + suspicious + undetected + harmless;

        Map<String, ScanResult.EngineResult> detections = new HashMap<>();
        JsonObject results = attributes.getAsJsonObject("results");
        if (results != null) {
            for (Map.Entry<String, JsonElement> entry : results.entrySet()) {
                JsonObject engineObj = entry.getValue().getAsJsonObject();
                String category = engineObj.has("category") && !engineObj.get("category").isJsonNull()
                        ? engineObj.get("category").getAsString() : "unknown";
                String result = engineObj.has("result") && !engineObj.get("result").isJsonNull()
                        ? engineObj.get("result").getAsString() : null;

                if ("malicious".equals(category) || "suspicious".equals(category)) {
                    detections.put(entry.getKey(), new ScanResult.EngineResult(category, result));
                }
            }
        }

        String vtLink = sha256 != null
                ? "https://www.virustotal.com/gui/file/" + sha256
                : "https://www.virustotal.com";

        return new ScanResult(fileName, sha256, malicious, suspicious, undetected, total, detections, vtLink);
    }

    private String requireBody(Response response) throws IOException {
        if (!response.isSuccessful()) {
            String errBody = response.body() != null ? response.body().string() : "(no body)";
            throw new IOException("VirusTotal API error " + response.code() + ": " + errBody);
        }
        ResponseBody body = response.body();
        if (body == null) throw new IOException("Empty response from VirusTotal");
        return body.string();
    }
}
