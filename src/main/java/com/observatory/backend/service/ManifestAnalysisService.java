package com.observatory.backend.service;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.*;
import java.util.stream.Stream;

@Service
public class ManifestAnalysisService {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public static class AnalysisResult {
        @JsonProperty("name") private String name = "Unknown Extension";
        @JsonProperty("version") private String version = "1.0.0";
        @JsonProperty("manifestVersion") private int manifestVersion = 3;
        @JsonProperty("permissions") private List<String> permissions = new ArrayList<>();
        @JsonProperty("riskScore") private int riskScore = 10;
        @JsonProperty("versionDiff") private String versionDiff = "";
        @JsonProperty("sbomFindings") private String sbomFindings = "";
        @JsonProperty("hash") private String hash = "N/A"; // <--- Add hash field

        public AnalysisResult() {}

        public AnalysisResult(String name, String version, int manifestVersion, List<String> permissions, int riskScore, String versionDiff, String sbomFindings, String hash) {
            this.name = name;
            this.version = version;
            this.manifestVersion = manifestVersion;
            this.permissions = permissions;
            this.riskScore = riskScore;
            this.versionDiff = versionDiff;
            this.sbomFindings = sbomFindings;
            this.hash = hash;
        }

        public String getName() { return name; }
        public String getVersion() { return version; }
        public int getManifestVersion() { return manifestVersion; }
        public List<String> getPermissions() { return permissions; }
        public int getRiskScore() { return riskScore; }
        public String getVersionDiff() { return versionDiff; }
        public String getSbomFindings() { return sbomFindings; }
        public String getHash() { return hash; } // <--- Getter

        public void setName(String name) { this.name = name; }
        public void setVersion(String version) { this.version = version; }
        public void setManifestVersion(int manifestVersion) { this.manifestVersion = manifestVersion; }
        public void setPermissions(List<String> permissions) { this.permissions = permissions; }
        public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
        public void setVersionDiff(String versionDiff) { this.versionDiff = versionDiff; }
        public void setSbomFindings(String sbomFindings) { this.sbomFindings = sbomFindings; }
        public void setHash(String hash) { this.hash = hash; } // <--- Setter
    }

    // Overload or update signature if you pass MultipartFile/file bytes into analysis
    public AnalysisResult analyzeManifest(File sandboxDir, MultipartFile file) {
        String calculatedHash = "N/A";
        if (file != null && !file.isEmpty()) {
            calculatedHash = calculateSha256(file);
        } else if (sandboxDir != null && sandboxDir.exists()) {
            // Optional fallback if calculating hash from directory root zip/crx, or keep N/A if handled in controller
        }

        File manifestFile = findManifestFile(sandboxDir);
        if (manifestFile == null || !manifestFile.exists()) {
            return new AnalysisResult("Unknown Extension", "1.0.0", 3, List.of(), 0, "No baseline available.", "No dependencies scanned.", calculatedHash);
        }

        try {
            JsonNode root = objectMapper.readTree(manifestFile);
            String name = root.path("name").asText("Test Extension");
            String version = root.path("version").asText("1.0.0");
            int manifestVersion = root.path("manifest_version").asInt(3);

            List<String> permissions = new ArrayList<>();
            if (root.has("permissions") && root.get("permissions").isArray()) {
                root.get("permissions").forEach(p -> permissions.add(p.asText()));
            }
            if (root.has("host_permissions") && root.get("host_permissions").isArray()) {
                root.get("host_permissions").forEach(hp -> permissions.add("host: " + hp.asText()));
            }

            Set<String> baselinePermissions = Set.of("storage", "activeTab");
            Set<String> targetPermissions = new HashSet<>(permissions);

            Set<String> addedPermissions = new HashSet<>(targetPermissions);
            addedPermissions.removeAll(baselinePermissions);
            Set<String> removedPermissions = new HashSet<>(baselinePermissions);
            removedPermissions.removeAll(targetPermissions);

            StringBuilder diffBuilder = new StringBuilder();
            diffBuilder.append("Baseline (v1.0.0) -> Target (v").append(version).append(")\n");
            if (!addedPermissions.isEmpty()) diffBuilder.append("[+] Added: ").append(addedPermissions).append("\n");
            if (!removedPermissions.isEmpty()) diffBuilder.append("[-] Removed: ").append(removedPermissions).append("\n");
            if (addedPermissions.isEmpty() && removedPermissions.isEmpty()) diffBuilder.append("[=] No permission changes.");

            int calculatedRisk = 10;
            for (String perm : permissions) {
                if (perm.equals("storage") || perm.equals("activeTab")) calculatedRisk += 10;
                else if (perm.equals("cookies") || perm.equals("webRequest")) calculatedRisk += 25;
                else if (perm.contains("<all_urls>") || perm.contains("*://*/*")) calculatedRisk += 35;
            }
            calculatedRisk = Math.min(calculatedRisk, 100);

            String sbomFindings = executeGrypeScan(sandboxDir);
            return new AnalysisResult(name, version, manifestVersion, permissions, calculatedRisk, diffBuilder.toString().trim(), sbomFindings, calculatedHash);

        } catch (IOException e) {
            return new AnalysisResult("Error Parsing", "1.0.0", 3, List.of(), 0, "Error reading diff.", "Error parsing SBOM.", calculatedHash);
        }
    }

    // Helper method placed right inside the service class
    private String calculateSha256(MultipartFile file) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(file.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "N/A";
        }
    }

    private String executeGrypeScan(File sandboxDir) {
        StringBuilder output = new StringBuilder();
        try {
            ProcessBuilder processBuilder = new ProcessBuilder("grype", "dir:" + sandboxDir.getAbsolutePath(), "-o", "json");
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }
            process.waitFor();
        } catch (Exception e) {
            return "Syft/Grype CLI tools not found locally or failed. Error: " + e.getMessage();
        }
        return output.length() > 0 ? output.toString().trim() : "Syft+Grype Scan: Clean dependency tree.";
    }

    private File findManifestFile(File dir) {
        try (Stream<Path> stream = Files.walk(dir.toPath())) {
            Optional<Path> match = stream.filter(p -> {
                String fileName = p.getFileName().toString().toLowerCase();
                return fileName.equals("manifest.json") || fileName.equals("manifest.json.txt");
            }).findFirst();
            return match.map(Path::toFile).orElse(null);
        } catch (IOException e) {
            return null;
        }
    }
}