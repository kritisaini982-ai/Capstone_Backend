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

    // =========================================================
    // TASK 4 - VERSION DIFF BASELINE STORAGE
    // =========================================================
    // Stores the latest scanned manifest permissions for each
    // extension name so the next scan can detect changes.

    private final Map<String, ManifestSnapshot> manifestBaselines =
            new HashMap<>();

    private static class ManifestSnapshot {

        private final String version;
        private final Set<String> permissions;

        private ManifestSnapshot(
                String version,
                Set<String> permissions) {

            this.version = version;
            this.permissions = new HashSet<>(permissions);
        }
    }

    // =========================================================
    // PERMISSION FINDING
    // =========================================================

    public static class PermissionFinding {

        private String permission;
        private String category;
        private String severity;
        private boolean excessive;
        private String reason;

        public PermissionFinding() {
        }

        public PermissionFinding(
                String permission,
                String category,
                String severity,
                boolean excessive,
                String reason) {

            this.permission = permission;
            this.category = category;
            this.severity = severity;
            this.excessive = excessive;
            this.reason = reason;
        }

        public String getPermission() {
            return permission;
        }

        public void setPermission(String permission) {
            this.permission = permission;
        }

        public String getCategory() {
            return category;
        }

        public void setCategory(String category) {
            this.category = category;
        }

        public String getSeverity() {
            return severity;
        }

        public void setSeverity(String severity) {
            this.severity = severity;
        }

        public boolean isExcessive() {
            return excessive;
        }

        public void setExcessive(boolean excessive) {
            this.excessive = excessive;
        }

        public String getReason() {
            return reason;
        }

        public void setReason(String reason) {
            this.reason = reason;
        }
    }

    // =========================================================
    // TASK 2 - REMOTE DOMAIN FINDING
    // =========================================================

    public static class RemoteDomainFinding {

        private String domain;
        private String scheme;
        private String source;
        private String scope;
        private String riskLevel;

        public RemoteDomainFinding() {
        }

        public RemoteDomainFinding(
                String domain,
                String scheme,
                String source,
                String scope,
                String riskLevel) {

            this.domain = domain;
            this.scheme = scheme;
            this.source = source;
            this.scope = scope;
            this.riskLevel = riskLevel;
        }

        public String getDomain() {
            return domain;
        }

        public void setDomain(String domain) {
            this.domain = domain;
        }

        public String getScheme() {
            return scheme;
        }

        public void setScheme(String scheme) {
            this.scheme = scheme;
        }

        public String getSource() {
            return source;
        }

        public void setSource(String source) {
            this.source = source;
        }

        public String getScope() {
            return scope;
        }

        public void setScope(String scope) {
            this.scope = scope;
        }

        public String getRiskLevel() {
            return riskLevel;
        }

        public void setRiskLevel(String riskLevel) {
            this.riskLevel = riskLevel;
        }
    }

    // =========================================================
    // ANALYSIS RESULT
    // =========================================================

    public static class AnalysisResult {

        @JsonProperty("name")
        private String name = "Unknown Extension";

        @JsonProperty("version")
        private String version = "1.0.0";

        @JsonProperty("manifestVersion")
        private int manifestVersion = 3;

        @JsonProperty("permissions")
        private List<String> permissions = new ArrayList<>();

        @JsonProperty("remoteDomains")
        private List<RemoteDomainFinding> remoteDomains =
        new ArrayList<>();

@JsonProperty("permissionFindings")
private List<PermissionFinding> permissionFindings =
        new ArrayList<>();

        @JsonProperty("excessivePermissions")
        private List<String> excessivePermissions =
                new ArrayList<>();

        @JsonProperty("leastPrivilegeScore")
        private int leastPrivilegeScore = 100;

        @JsonProperty("riskScore")
        private int riskScore = 10;

        @JsonProperty("versionDiff")
        private String versionDiff = "";

        @JsonProperty("sbomFindings")
        private String sbomFindings = "";

        @JsonProperty("hash")
        private String hash = "N/A";

        public AnalysisResult() {
        }

        public AnalysisResult(
        String name,
        String version,
        int manifestVersion,
        List<String> permissions,
        List<RemoteDomainFinding> remoteDomains,
        List<PermissionFinding> permissionFindings,
        List<String> excessivePermissions,
        int leastPrivilegeScore,
        int riskScore,
        String versionDiff,
        String sbomFindings,
        String hash) {

            this.name = name;
            this.version = version;
            this.manifestVersion = manifestVersion;
            this.permissions = permissions;
            this.remoteDomains = remoteDomains;
            this.permissionFindings = permissionFindings;
            this.excessivePermissions = excessivePermissions;
            this.leastPrivilegeScore = leastPrivilegeScore;
            this.riskScore = riskScore;
            this.versionDiff = versionDiff;
            this.sbomFindings = sbomFindings;
            this.hash = hash;
        }

        public String getName() {
            return name;
        }

        public String getVersion() {
            return version;
        }

        public int getManifestVersion() {
            return manifestVersion;
        }

        public List<String> getPermissions() {
            return permissions;
        }

        public List<RemoteDomainFinding> getRemoteDomains() {
        return remoteDomains;
        }

        public List<PermissionFinding> getPermissionFindings() {
            return permissionFindings;
        }

        public List<String> getExcessivePermissions() {
            return excessivePermissions;
        }

        public int getLeastPrivilegeScore() {
            return leastPrivilegeScore;
        }

        public int getRiskScore() {
            return riskScore;
        }

        public String getVersionDiff() {
            return versionDiff;
        }

        public String getSbomFindings() {
            return sbomFindings;
        }

        public String getHash() {
            return hash;
        }

        public void setName(String name) {
            this.name = name;
        }

        public void setVersion(String version) {
            this.version = version;
        }

        public void setManifestVersion(int manifestVersion) {
            this.manifestVersion = manifestVersion;
        }

        public void setPermissions(List<String> permissions) {
            this.permissions = permissions;
        
        }
        public void setRemoteDomains(
        List<RemoteDomainFinding> remoteDomains) {
    this.remoteDomains = remoteDomains;
}
        public void setPermissionFindings(
                List<PermissionFinding> permissionFindings) {

            this.permissionFindings = permissionFindings;
        }

        public void setExcessivePermissions(
                List<String> excessivePermissions) {

            this.excessivePermissions = excessivePermissions;
        }

        public void setLeastPrivilegeScore(int leastPrivilegeScore) {
            this.leastPrivilegeScore = leastPrivilegeScore;
        }

        public void setRiskScore(int riskScore) {
            this.riskScore = riskScore;
        }

        public void setVersionDiff(String versionDiff) {
            this.versionDiff = versionDiff;
        }

        public void setSbomFindings(String sbomFindings) {
            this.sbomFindings = sbomFindings;
        }

        public void setHash(String hash) {
            this.hash = hash;
        }
    }

    // =========================================================
    // MAIN MANIFEST ANALYSIS
    // =========================================================

    public AnalysisResult analyzeManifest(
            File sandboxDir,
            MultipartFile file) {

        String calculatedHash = "N/A";

        // =====================================================
        // SHA-256
        // =====================================================

        if (file != null && !file.isEmpty()) {
            calculatedHash = calculateSha256(file);
        }

        // =====================================================
        // FIND MANIFEST
        // =====================================================

        File manifestFile = findManifestFile(sandboxDir);

        if (manifestFile == null || !manifestFile.exists()) {

          return new AnalysisResult(
        "Unknown Extension",
        "1.0.0",
        3,
        List.of(),
        List.of(),
        List.of(),
        List.of(),
        100,
        0,
        "No baseline available.",
        "No dependencies scanned.",
        calculatedHash
);
        }

        try {

            // =================================================
            // READ MANIFEST
            // =================================================

            JsonNode root =
                    objectMapper.readTree(manifestFile);

            String name =
                    root.path("name")
                            .asText("Test Extension");

            String version =
                    root.path("version")
                            .asText("1.0.0");

            int manifestVersion =
                    root.path("manifest_version")
                            .asInt(3);

            // =================================================
            // EXTRACT PERMISSIONS
            // =================================================

            List<String> permissions =
                    new ArrayList<>();

            if (root.has("permissions")
                    && root.get("permissions").isArray()) {

                root.get("permissions").forEach(
                        p -> permissions.add(p.asText())
                );
            }

            // =================================================
            // EXTRACT HOST PERMISSIONS
            // =================================================

            if (root.has("host_permissions")
                    && root.get("host_permissions").isArray()) {

                root.get("host_permissions").forEach(
                        hp -> permissions.add(
                                "host: " + hp.asText()
                        )
                );
            }

            // =================================================
            // TASK 1 - LEAST PRIVILEGE
            // =================================================

            List<PermissionFinding> permissionFindings =
                    analyzeLeastPrivilege(permissions);

            List<String> excessivePermissions =
                    permissionFindings.stream()
                            .filter(PermissionFinding::isExcessive)
                            .map(PermissionFinding::getPermission)
                            .toList();

            int leastPrivilegeScore =
                    calculateLeastPrivilegeScore(
                            permissionFindings
                    );

            // =================================================
            // TASK 2 - REMOTE DOMAIN INVENTORY
            // =================================================

            List<RemoteDomainFinding> remoteDomains =
                    analyzeRemoteDomains(root);

            // =================================================
            // TASK 4 - REAL VERSION DIFFERENCE
            // =================================================

            Set<String> normalizedTargetPermissions =
                    new TreeSet<>();

            for (String permission : permissions) {

                if (permission == null) {
                    continue;
                }

                String normalized =
                        permission.trim().toLowerCase();

                if (!normalized.isEmpty()) {
                    normalizedTargetPermissions.add(
                            normalized
                    );
                }
            }

            // -------------------------------------------------
            // GET PREVIOUS BASELINE
            // -------------------------------------------------

            ManifestSnapshot previousSnapshot =
                    manifestBaselines.get(name);

            StringBuilder diffBuilder =
                    new StringBuilder();

            if (previousSnapshot == null) {

                // =================================================
                // FIRST SCAN
                // =================================================

                diffBuilder
                        .append("Initial Baseline Created\n")
                        .append("Version: v")
                        .append(version)
                        .append("\n")
                        .append(
                                "[=] No previous version available for comparison."
                        );

            } else {

                // =================================================
                // COMPARE AGAINST PREVIOUS SCAN
                // =================================================

                Set<String> addedPermissions =
                        new TreeSet<>(
                                normalizedTargetPermissions
                        );

                addedPermissions.removeAll(
                        previousSnapshot.permissions
                );

                Set<String> removedPermissions =
                        new TreeSet<>(
                                previousSnapshot.permissions
                        );

                removedPermissions.removeAll(
                        normalizedTargetPermissions
                );

                diffBuilder
                        .append("Baseline (v")
                        .append(previousSnapshot.version)
                        .append(") -> Target (v")
                        .append(version)
                        .append(")\n");

                // -------------------------------------------------
                // ADDED PERMISSIONS
                // -------------------------------------------------

                if (!addedPermissions.isEmpty()) {

                    diffBuilder
                            .append("[+] Added Permissions: ")
                            .append(addedPermissions)
                            .append("\n");
                }

                // -------------------------------------------------
                // REMOVED PERMISSIONS
                // -------------------------------------------------

                if (!removedPermissions.isEmpty()) {

                    diffBuilder
                            .append("[-] Removed Permissions: ")
                            .append(removedPermissions)
                            .append("\n");
                }

                // -------------------------------------------------
                // NO CHANGES
                // -------------------------------------------------

                if (addedPermissions.isEmpty()
                        && removedPermissions.isEmpty()) {

                    diffBuilder.append(
                            "[=] No permission changes."
                    );
                }
            }

            // =================================================
            // UPDATE BASELINE
            // =================================================

            manifestBaselines.put(
                    name,
                    new ManifestSnapshot(
                            version,
                            normalizedTargetPermissions
                    )
            );

            // =================================================
            // RISK SCORE
            // =================================================

            int calculatedRisk = 10;

            for (String perm : permissions) {

                String normalized =
                        perm.trim().toLowerCase();

                if (normalized.equals("storage")
                        || normalized.equals("activetab")) {

                    calculatedRisk += 10;

                } else if (normalized.equals("cookies")
                        || normalized.equals("webrequest")) {

                    calculatedRisk += 25;

                } else if (
                        normalized.contains("<all_urls>")
                                || normalized.contains("*://*/*")) {

                    calculatedRisk += 35;
                }
            }

            // =================================================
            // LEAST PRIVILEGE PENALTY
            // =================================================

            int excessivePermissionPenalty =
                    (100 - leastPrivilegeScore) / 2;

            calculatedRisk +=
                    excessivePermissionPenalty;

            calculatedRisk =
                    Math.min(
                            calculatedRisk,
                            100
                    );

            // =================================================
            // TASK 3 - SYFT / GRYPE
            // =================================================

            String sbomFindings =
                    executeGrypeScan(sandboxDir);

            // =================================================
            // RETURN RESULT
            // =================================================

            return new AnalysisResult(
        name,
        version,
        manifestVersion,
        permissions,
        remoteDomains,
        permissionFindings,
        excessivePermissions,
        leastPrivilegeScore,
        calculatedRisk,
        diffBuilder.toString().trim(),
        sbomFindings,
        calculatedHash
);

        } catch (IOException e) {

          return new AnalysisResult(
        "Error Parsing",
        "1.0.0",
        3,
        List.of(),
        List.of(),
        List.of(),
        List.of(),
        100,
        0,
        "Error reading diff.",
        "Error parsing SBOM.",
        calculatedHash
);
        }
    }

    // =========================================================
    // TASK 1 - LEAST PRIVILEGE ANALYSIS
    // =========================================================

    public List<PermissionFinding> analyzeLeastPrivilege(
            List<String> permissions) {

        List<PermissionFinding> findings =
                new ArrayList<>();

        for (String permission : permissions) {

            if (permission == null) {
                continue;
            }

            String normalized =
                    permission.trim().toLowerCase();

            // =================================================
            // STORAGE
            // =================================================

            if (normalized.equals("storage")) {

                findings.add(
                        new PermissionFinding(
                                permission,
                                "Storage",
                                "LOW",
                                false,
                                "Storage access is commonly required for extension settings and local data."
                        )
                );

            // =================================================
            // ACTIVE TAB
            // =================================================

            } else if (normalized.equals("activetab")) {

                findings.add(
                        new PermissionFinding(
                                permission,
                                "Tab Access",
                                "MEDIUM",
                                false,
                                "activeTab provides temporary access to the currently active tab."
                        )
                );

            // =================================================
            // TABS
            // =================================================

            } else if (normalized.equals("tabs")) {

                findings.add(
                        new PermissionFinding(
                                permission,
                                "Browser Tab Access",
                                "HIGH",
                                true,
                                "The tabs permission provides broad access to browser tab information and should be justified."
                        )
                );

            // =================================================
            // COOKIES
            // =================================================

            } else if (normalized.equals("cookies")) {

                findings.add(
                        new PermissionFinding(
                                permission,
                                "Cookie Access",
                                "HIGH",
                                true,
                                "Cookie access can expose sensitive authentication and session information."
                        )
                );

            // =================================================
            // WEB REQUEST
            // =================================================

            } else if (normalized.equals("webrequest")) {

                findings.add(
                        new PermissionFinding(
                                permission,
                                "Network Monitoring",
                                "HIGH",
                                true,
                                "webRequest can observe browser network activity and requires strong justification."
                        )
                );

            // =================================================
            // WEB REQUEST BLOCKING
            // =================================================

            } else if (normalized.equals(
                    "webrequestblocking")) {

                findings.add(
                        new PermissionFinding(
                                permission,
                                "Network Modification",
                                "CRITICAL",
                                true,
                                "webRequestBlocking can modify network requests and represents elevated browser privilege."
                        )
                );

            // =================================================
            // UNIVERSAL HOST ACCESS
            // =================================================

            } else if (
                    normalized.contains("<all_urls>")
                            || normalized.contains("*://*/*")) {

                findings.add(
                        new PermissionFinding(
                                permission,
                                "Universal Host Access",
                                "CRITICAL",
                                true,
                                "Universal host access allows the extension to interact with pages across broad website scopes."
                        )
                );

            // =================================================
            // NORMAL HOST ACCESS
            // =================================================

            } else if (normalized.startsWith("host:")) {

                findings.add(
                        new PermissionFinding(
                                permission,
                                "Host Access",
                                "MEDIUM",
                                false,
                                "Host access should be limited to domains required by the extension's functionality."
                        )
                );

            // =================================================
            // OTHER PERMISSIONS
            // =================================================

            } else {

                findings.add(
                        new PermissionFinding(
                                permission,
                                "Other Browser Permission",
                                "MEDIUM",
                                false,
                                "This permission requires review to determine whether it is necessary for the extension."
                        )
                );
            }
        }

        return findings;
    }

    // =========================================================
    // LEAST PRIVILEGE SCORE
    // =========================================================

    public int calculateLeastPrivilegeScore(
            List<PermissionFinding> findings) {

        int penalty = 0;

        for (PermissionFinding finding : findings) {

            if (!finding.isExcessive()) {
                continue;
            }

            switch (finding.getSeverity()) {

                case "CRITICAL":
                    penalty += 30;
                    break;

                case "HIGH":
                    penalty += 20;
                    break;

                case "MEDIUM":
                    penalty += 10;
                    break;

                default:
                    penalty += 5;
                    break;
            }
        }

        return Math.max(
                0,
                100 - Math.min(
                        penalty,
                        100
                )
        );
    }

    // =========================================================
    // TASK 2 - REMOTE DOMAIN INVENTORY
    // =========================================================

    public List<RemoteDomainFinding> analyzeRemoteDomains(
            JsonNode root) {

        Map<String, RemoteDomainFinding> inventory =
                new LinkedHashMap<>();

        // =====================================================
        // HOST PERMISSIONS
        // =====================================================

        if (root.has("host_permissions")
                && root.get("host_permissions").isArray()) {

            for (JsonNode node :
                    root.get("host_permissions")) {

                String value =
                        node.asText();

                if (isUrlPattern(value)
                        || value.contains("<all_urls>")) {

                    addRemoteDomain(
                            inventory,
                            value,
                            "host_permissions"
                    );
                }
            }
        }

        // =====================================================
        // LEGACY URL PATTERNS IN permissions
        // =====================================================

        if (root.has("permissions")
                && root.get("permissions").isArray()) {

            for (JsonNode node :
                    root.get("permissions")) {

                String value =
                        node.asText();

                if (isUrlPattern(value)
                        || value.contains("<all_urls>")) {

                    addRemoteDomain(
                            inventory,
                            value,
                            "permissions"
                    );
                }
            }
        }

        // =====================================================
        // CONTENT SCRIPTS
        // =====================================================

        if (root.has("content_scripts")
                && root.get("content_scripts").isArray()) {

            for (JsonNode contentScript :
                    root.get("content_scripts")) {

                if (contentScript.has("matches")
                        && contentScript.get("matches").isArray()) {

                    for (JsonNode match :
                            contentScript.get("matches")) {

                        String value =
                                match.asText();

                        if (isUrlPattern(value)
                                || value.contains("<all_urls>")) {

                            addRemoteDomain(
                                    inventory,
                                    value,
                                    "content_scripts.matches"
                            );
                        }
                    }
                }
            }
        }

        // =====================================================
        // EXTERNALLY CONNECTABLE
        // =====================================================

        if (root.has("externally_connectable")) {

            JsonNode externallyConnectable =
                    root.get("externally_connectable");

            if (externallyConnectable.has("matches")
                    && externallyConnectable.get("matches").isArray()) {

                for (JsonNode match :
                        externallyConnectable.get("matches")) {

                    String value =
                            match.asText();

                    if (isUrlPattern(value)
                            || value.contains("<all_urls>")) {

                        addRemoteDomain(
                                inventory,
                                value,
                                "externally_connectable.matches"
                        );
                    }
                }
            }
        }

        return new ArrayList<>(
                inventory.values()
        );
    }

    // =========================================================
    // TASK 2 - URL PATTERN CHECK
    // =========================================================

    private boolean isUrlPattern(
            String value) {

        if (value == null) {
            return false;
        }

        String normalized =
                value.trim().toLowerCase();

        return normalized.startsWith("http://")
                || normalized.startsWith("https://")
                || normalized.startsWith("*://");
    }

    // =========================================================
    // TASK 2 - ADD REMOTE DOMAIN
    // =========================================================

    private void addRemoteDomain(
            Map<String, RemoteDomainFinding> inventory,
            String value,
            String source) {

        if (value == null
                || value.trim().isEmpty()) {

            return;
        }

        String original =
                value.trim();

        String normalized =
                original.toLowerCase();

        // =====================================================
        // UNIVERSAL ACCESS
        // =====================================================

        if (normalized.contains("<all_urls>")
                || normalized.contains("*://*/*")) {

            String key =
                    "universal";

            if (!inventory.containsKey(key)) {

                inventory.put(
                        key,
                        new RemoteDomainFinding(
                                "<all_urls>",
                                "*",
                                source,
                                "Universal / All Websites",
                                "CRITICAL"
                        )
                );
            }

            return;
        }

        // =====================================================
        // EXTRACT SCHEME
        // =====================================================

        String scheme = "*";

        if (normalized.startsWith("https://")) {

            scheme = "HTTPS";

        } else if (normalized.startsWith("http://")) {

            scheme = "HTTP";

        } else if (normalized.startsWith("*://")) {

            scheme = "*";
        }

        // =====================================================
        // REMOVE SCHEME
        // =====================================================

        String domain =
                original
                        .replaceFirst(
                                "(?i)^https?://",
                                ""
                        )
                        .replaceFirst(
                                "^\\*://",
                                ""
                        );

        // =====================================================
        // REMOVE PATH
        // =====================================================

        int slashIndex =
                domain.indexOf('/');

        if (slashIndex >= 0) {

            domain =
                    domain.substring(
                            0,
                            slashIndex
                    );
        }

        // =====================================================
        // REMOVE QUERY
        // =====================================================

        int questionIndex =
                domain.indexOf('?');

        if (questionIndex >= 0) {

            domain =
                    domain.substring(
                            0,
                            questionIndex
                    );
        }

        // =====================================================
        // REMOVE FRAGMENT
        // =====================================================

        int fragmentIndex =
                domain.indexOf('#');

        if (fragmentIndex >= 0) {

            domain =
                    domain.substring(
                            0,
                            fragmentIndex
                    );
        }

        domain =
                domain.trim();

        if (domain.isEmpty()) {
            return;
        }

        // =====================================================
        // CLASSIFY SCOPE
        // =====================================================

        String scope;
        String riskLevel;

        if (domain.startsWith("*.")) {

            scope =
                    "Wildcard Subdomain";

            riskLevel =
                    "HIGH";

        } else {

            scope =
                    "Specific Domain";

            riskLevel =
                    "MEDIUM";
        }

        // =====================================================
        // UNIQUE KEY
        // =====================================================

        String key =
                scheme.toLowerCase()
                        + ":"
                        + domain.toLowerCase();

        // =====================================================
        // ADD FINDING
        // =====================================================

        if (!inventory.containsKey(key)) {

            inventory.put(
                    key,
                    new RemoteDomainFinding(
                            domain,
                            scheme,
                            source,
                            scope,
                            riskLevel
                    )
            );
        }
    }

    // =========================================================
    // SHA-256
    // =========================================================

    private String calculateSha256(
            MultipartFile file) {

        try {

            MessageDigest digest =
                    MessageDigest.getInstance(
                            "SHA-256"
                    );

            byte[] hashBytes =
                    digest.digest(
                            file.getBytes()
                    );

            StringBuilder sb =
                    new StringBuilder();

            for (byte b : hashBytes) {

                sb.append(
                        String.format(
                                "%02x",
                                b
                        )
                );
            }

            return sb.toString();

        } catch (Exception e) {

            return "N/A";
        }
    }

    // =========================================================
    // TASK 3 - SYFT SBOM + GRYPE
    // =========================================================

    public String scanDependencies(
            File sandboxDir) {

        return executeGrypeScan(
                sandboxDir
        );
    }

  private String executeGrypeScan(
        File sandboxDir) {

    if (sandboxDir == null
            || !sandboxDir.exists()) {

        return "SBOM scan skipped: sandbox directory not found.";
    }

    File sbomFile = null;

    try {

        // =====================================================
        // STEP 1 - GENERATE SBOM USING SYFT
        // =====================================================

        sbomFile =
                File.createTempFile(
                        "observatory-sbom-",
                        ".json",
                        sandboxDir
                );

        ProcessBuilder syftProcessBuilder =
                new ProcessBuilder(
                        "syft",
                        sandboxDir.getAbsolutePath(),
                        "--select-catalogers",
                        "javascript",
                        "--parallelism",
                        "8",
                        "-q",
                        "-o",
                        "cyclonedx-json"
                );

        // Disable Syft application update check
        syftProcessBuilder.environment().put(
                "SYFT_CHECK_FOR_APP_UPDATE",
                "false"
        );

        // Disable file metadata collection
        syftProcessBuilder.environment().put(
                "SYFT_FILE_METADATA_SELECTION",
                "none"
        );

        syftProcessBuilder.redirectOutput(
                sbomFile
        );

        syftProcessBuilder.redirectError(
                ProcessBuilder.Redirect.DISCARD
        );

        // -----------------------------------------------------
        // SYFT TIMING
        // -----------------------------------------------------

        long syftStart =
                System.nanoTime();

        Process syftProcess =
                syftProcessBuilder.start();

        int syftExitCode =
                syftProcess.waitFor();

        long syftTimeMs =
                (System.nanoTime() - syftStart)
                        / 1_000_000;

        System.out.println(
                "SBOM SCAN - Syft time: "
                        + syftTimeMs
                        + " ms"
        );

        if (syftExitCode != 0) {

            return "Syft SBOM generation failed. Exit code: "
                    + syftExitCode;
        }

        if (!sbomFile.exists()
                || sbomFile.length() == 0) {

            return "Syft generated an empty SBOM.";
        }

        // =====================================================
        // STEP 2 - GRYPE VULNERABILITY SCAN
        // =====================================================

        ProcessBuilder grypeProcessBuilder =
                new ProcessBuilder(
                        "grype",
                        "sbom:" + sbomFile.getAbsolutePath(),
                        "-o",
                        "json"
                );

        // Use existing local Grype database
        grypeProcessBuilder.environment().put(
                "GRYPE_DB_AUTO_UPDATE",
                "false"
        );

        // Disable Grype application update check
        grypeProcessBuilder.environment().put(
                "GRYPE_CHECK_FOR_APP_UPDATE",
                "false"
        );

        grypeProcessBuilder.redirectErrorStream(
                true
        );

        // -----------------------------------------------------
        // GRYPE TIMING
        // -----------------------------------------------------

        long grypeStart =
                System.nanoTime();

        Process grypeProcess =
                grypeProcessBuilder.start();

        StringBuilder grypeOutput =
                new StringBuilder();

        try (
                BufferedReader reader =
                        new BufferedReader(
                                new InputStreamReader(
                                        grypeProcess
                                                .getInputStream()
                                )
                        )
        ) {

            String line;

            while (
                    (line = reader.readLine())
                            != null
            ) {

                grypeOutput
                        .append(line)
                        .append("\n");
            }
        }

        int grypeExitCode =
                grypeProcess.waitFor();

        long grypeTimeMs =
                (System.nanoTime() - grypeStart)
                        / 1_000_000;

        System.out.println(
                "SBOM SCAN - Grype time: "
                        + grypeTimeMs
                        + " ms"
        );

        System.out.println(
                "SBOM SCAN - Total Syft + Grype time: "
                        + (syftTimeMs + grypeTimeMs)
                        + " ms"
        );

        // =====================================================
        // STEP 3 - RETURN RESULT
        // =====================================================

        if (grypeOutput.length() == 0) {

            return "Syft SBOM generated successfully, but Grype returned no output.";
        }

        return "SYFT SBOM GENERATED: "
                + sbomFile.length()
                + " bytes\n"
                + "GRYPE EXIT CODE: "
                + grypeExitCode
                + "\n"
                + grypeOutput
                        .toString()
                        .trim();

    } catch (Exception e) {

        return "Syft/Grype CLI execution failed: "
                + e.getMessage();

    } finally {

        // =====================================================
        // CLEAN TEMPORARY SBOM
        // =====================================================

        if (sbomFile != null
                && sbomFile.exists()) {

            try {

                Files.deleteIfExists(
                        sbomFile.toPath()
                );

            } catch (IOException ignored) {

                // Cleanup failure should not
                // break the scan response.
            }
        }
    }
}

    // =========================================================
    // FIND MANIFEST
    // =========================================================

    private File findManifestFile(
            File dir) {

        if (dir == null
                || !dir.exists()) {

            return null;
        }

        try (
                Stream<Path> stream =
                        Files.walk(
                                dir.toPath()
                        )
        ) {

            Optional<Path> match =
                    stream
                            .filter(p -> {

                                String fileName =
                                        p.getFileName()
                                                .toString()
                                                .toLowerCase();

                                return fileName.equals(
                                                "manifest.json"
                                        )
                                        || fileName.equals(
                                                "manifest.json.txt"
                                        );
                            })
                            .findFirst();

            return match
                    .map(Path::toFile)
                    .orElse(null);

        } catch (IOException e) {

            return null;
        }
    }
}