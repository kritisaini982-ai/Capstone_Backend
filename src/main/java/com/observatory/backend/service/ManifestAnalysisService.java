package com.observatory.backend.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

@Service
public class ManifestAnalysisService {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public static class AnalysisResult {
        private String name;
        private String version;
        private int manifestVersion;
        private List<String> permissions;
        private int riskScore;

        public AnalysisResult() {}

        public AnalysisResult(String name, String version, int manifestVersion, List<String> permissions, int riskScore) {
            this.name = name;
            this.version = version;
            this.manifestVersion = manifestVersion;
            this.permissions = permissions;
            this.riskScore = riskScore;
        }

        public String getName() { return name; }
        public String getVersion() { return version; }
        public int getManifestVersion() { return manifestVersion; }
        public List<String> getPermissions() { return permissions; }
        public int getRiskScore() { return riskScore; }
    }

    public AnalysisResult analyzeManifest(File sandboxDir) {
        File manifestFile = findManifestFile(sandboxDir);

        if (manifestFile == null || !manifestFile.exists()) {
            return new AnalysisResult("Unknown Extension", "1.0.0", 3, List.of(), 0);
        }

        try {
            JsonNode root = objectMapper.readTree(manifestFile);
            
            String name = root.path("name").asText("Test Extension");
            String version = root.path("version").asText("1.0.0");
            int manifestVersion = root.path("manifest_version").asInt(3);

            List<String> permissions = new ArrayList<>();

            // 1. Standard Manifest permissions
            if (root.has("permissions") && root.get("permissions").isArray()) {
                root.get("permissions").forEach(p -> permissions.add(p.asText()));
            }

            // 2. Manifest V3 host permissions (<all_urls>, *://*/*)
            if (root.has("host_permissions") && root.get("host_permissions").isArray()) {
                root.get("host_permissions").forEach(hp -> permissions.add("host: " + hp.asText()));
            }

            // Dynamic Risk Score Calculation
            int calculatedRisk = 10; // Base score

            for (String perm : permissions) {
                if (perm.equals("storage")) calculatedRisk += 10;
                if (perm.equals("activeTab")) calculatedRisk += 10;
                if (perm.equals("cookies")) calculatedRisk += 25;
                if (perm.equals("webRequest")) calculatedRisk += 25;
                if (perm.contains("<all_urls>") || perm.contains("*://*/*")) calculatedRisk += 35;
            }

            // Cap risk score at 100
            calculatedRisk = Math.min(calculatedRisk, 100);

            return new AnalysisResult(name, version, manifestVersion, permissions, calculatedRisk);

        } catch (IOException e) {
            return new AnalysisResult("Error Parsing", "1.0.0", 3, List.of(), 0);
        }
    }

    private File findManifestFile(File dir) {
        try (Stream<Path> stream = Files.walk(dir.toPath())) {
            Optional<Path> match = stream
                .filter(p -> {
                    String fileName = p.getFileName().toString().toLowerCase();
                    return fileName.equals("manifest.json") || fileName.equals("manifest.json.txt");
                })
                .findFirst();
            return match.map(Path::toFile).orElse(null);
        } catch (IOException e) {
            return null;
        }
    }
}