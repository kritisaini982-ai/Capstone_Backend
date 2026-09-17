package com.observatory.backend.model;

import com.observatory.backend.service.ManifestAnalysisService;
import java.util.List;

public class ExtensionAnalysisResponse {
    private String scanId;
    private String filename;
    private String status;
    private ManifestAnalysisService.AnalysisResult analysis;

    // Constructors
    public ExtensionAnalysisResponse() {}

    public ExtensionAnalysisResponse(String scanId, String filename, String status, ManifestAnalysisService.AnalysisResult analysis) {
        this.scanId = scanId;
        this.filename = filename;
        this.status = status;
        this.analysis = analysis;
    }

    // Getters and Setters
    public String getScanId() { return scanId; }
    public void setScanId(String scanId) { this.scanId = scanId; }

    public String getFilename() { return filename; }
    public void setFilename(String filename) { this.filename = filename; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public ManifestAnalysisService.AnalysisResult getAnalysis() { return analysis; }
    public void setAnalysis(ManifestAnalysisService.AnalysisResult analysis) { this.analysis = analysis; }
}