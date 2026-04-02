package com.vtbot.model;

import java.util.Map;
import java.util.TreeMap;

public class ScanResult {
    private final String fileName;
    private final String sha256;
    private final int malicious;
    private final int suspicious;
    private final int undetected;
    private final int totalEngines;
    private final Map<String, EngineResult> detections;
    private final String vtLink;

    public ScanResult(String fileName, String sha256,
                      int malicious, int suspicious, int undetected,
                      int totalEngines, Map<String, EngineResult> detections,
                      String vtLink) {
        this.fileName = fileName;
        this.sha256 = sha256;
        this.malicious = malicious;
        this.suspicious = suspicious;
        this.undetected = undetected;
        this.totalEngines = totalEngines;
        this.detections = new TreeMap<>(detections);
        this.vtLink = vtLink;
    }

    public String getFileName() { return fileName; }
    public String getSha256() { return sha256; }
    public int getMalicious() { return malicious; }
    public int getSuspicious() { return suspicious; }
    public int getUndetected() { return undetected; }
    public int getTotalEngines() { return totalEngines; }
    public Map<String, EngineResult> getDetections() { return detections; }
    public String getVtLink() { return vtLink; }

    public Verdict getVerdict() {
        if (malicious >= 5) return Verdict.MALICIOUS;
        if (malicious >= 1 || suspicious >= 3) return Verdict.SUSPICIOUS;
        return Verdict.CLEAN;
    }

    public enum Verdict {
        CLEAN, SUSPICIOUS, MALICIOUS
    }

    public record EngineResult(String category, String result) {}
}
