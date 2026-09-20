package com.observatory.backend.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.observatory.backend.model.ScanHistory;
import com.observatory.backend.model.AuditLog;
import com.observatory.backend.model.User;
import com.observatory.backend.repository.ScanHistoryRepository;
import com.observatory.backend.repository.UserRepository;
import com.observatory.backend.repository.AuditLogRepository;
import com.observatory.backend.service.ManifestAnalysisService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

@RestController
@RequestMapping("/api/v1")
@CrossOrigin(origins = "*")
public class FileUploadController {

    @Autowired
    private ScanHistoryRepository scanHistoryRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ManifestAnalysisService manifestAnalysisService;

    @Autowired
    private AuditLogRepository auditLogRepository;

    // =========================================================
    // FILE CACHE
    // =========================================================

    private final Map<String, byte[]> fileCache =
            new ConcurrentHashMap<>();

    private final Map<String, String> filenameCache =
            new ConcurrentHashMap<>();

    // =========================================================
    // ALLOWLIST CACHE
    // =========================================================

    private final Set<String> allowlistedScanIds =
            ConcurrentHashMap.newKeySet();

    // =========================================================
    // FILE STORAGE LOCATION
    // =========================================================

    private final Path fileStorageLocation =
            Paths.get("uploads")
                    .toAbsolutePath()
                    .normalize();

    // =========================================================
    // AUTHENTICATION - LOGIN
    // =========================================================

    @PostMapping("/auth/login")
    public ResponseEntity<Map<String, Object>> login(
            @RequestBody Map<String, String> credentials) {

        String email =
                credentials.get("email");

        String password =
                credentials.get("password");

        Map<String, Object> response =
                new HashMap<>();

        if (email == null || password == null) {
    response.put("message", "Email and password are required");
    return ResponseEntity.badRequest().body(response);
}

if (password.length() < 8) {
    response.put("message", "Password must be at least 8 characters long");
    return ResponseEntity.badRequest().body(response);
}

        Optional<User> userOpt =
                userRepository.findByEmail(email);

        if (userOpt.isPresent()
                && userOpt.get()
                .getPassword()
                .equals(password)) {

            response.put(
                    "token",
                    "mock-jwt-token-secure-12345"
            );

            response.put(
                    "message",
                    "Login successful"
            );

            return ResponseEntity.ok(response);
        }

        response.put(
                "message",
                "Invalid credentials"
        );

        return ResponseEntity
                .badRequest()
                .body(response);
    }

    // =========================================================
    // AUTHENTICATION - REGISTER
    // =========================================================

    @PostMapping("/auth/register")
    public ResponseEntity<Map<String, Object>> register(
            @RequestBody Map<String, String> credentials) {

        String email =
                credentials.get("email");

        String password =
                credentials.get("password");

        Map<String, Object> response =
                new HashMap<>();

        if (email == null || password == null) {

            response.put(
                    "message",
                    "Email and password are required"
            );

            return ResponseEntity
                    .badRequest()
                    .body(response);
        }

        if (userRepository
                .findByEmail(email)
                .isPresent()) {

            response.put(
                    "message",
                    "User already exists"
            );

            return ResponseEntity
                    .badRequest()
                    .body(response);
        }

        userRepository.save(
                new User(
                        email,
                        password
                )
        );

        response.put(
                "token",
                "mock-jwt-token-secure-12345"
        );

        response.put(
                "message",
                "User registered successfully"
        );

        return ResponseEntity.ok(response);
    }

    // =========================================================
    // EXTENSION ANALYSIS / UPLOAD
    // =========================================================

    @PostMapping("/extensions/upload")
    public Map<String, Object> uploadExtension(
            @RequestParam("file") MultipartFile file,
            @RequestParam(
                    value = "userEmail",
                    defaultValue = "anonymous"
            )
            String userEmail) {

        Map<String, Object> response =
                new HashMap<>();

        List<String> riskExplanations =
                new ArrayList<>();

        String filename =
                file != null
                        && file.getOriginalFilename() != null
                        ? file.getOriginalFilename()
                        : "extension.zip";

        String scanId =
                UUID.randomUUID()
                        .toString()
                        .substring(0, 8);

        File sandboxDir = null;

        byte[] fileBytes;

        // =====================================================
        // VALIDATE FILE
        // =====================================================

        if (file == null || file.isEmpty()) {

            response.put(
                    "status",
                    "ERROR"
            );

            response.put(
                    "message",
                    "Extension file is empty"
            );

            return response;
        }

        // =====================================================
        // READ FILE + CREATE SANDBOX
        // =====================================================

        try {

            fileBytes =
                    file.getBytes();

            sandboxDir =
                    Files.createTempDirectory(
                            "observatory-scan-"
                    ).toFile();

            Path sandboxRoot =
                    sandboxDir
                            .toPath()
                            .toAbsolutePath()
                            .normalize();

            // =================================================
            // SAFE ZIP EXTRACTION
            // =================================================

            try (
                    ZipInputStream extractIn =
                            new ZipInputStream(
                                    new java.io.ByteArrayInputStream(
                                            fileBytes
                                    )
                            )
            ) {

                ZipEntry entry;

                while (
                        (entry =
                                extractIn.getNextEntry())
                                != null
                ) {

                    Path target =
                            sandboxRoot
                                    .resolve(
                                            entry.getName()
                                    )
                                    .normalize();

                    // =================================================
                    // ZIP SLIP PROTECTION
                    // =================================================

                    if (!target.startsWith(
                            sandboxRoot)) {

                        throw new SecurityException(
                                "Invalid ZIP entry path: "
                                        + entry.getName()
                        );
                    }

                    if (entry.isDirectory()) {

                        Files.createDirectories(
                                target
                        );

                    } else {

                        if (target.getParent()
                                != null) {

                            Files.createDirectories(
                                    target.getParent()
                            );
                        }

                        Files.copy(
                                extractIn,
                                target,
                                java.nio.file
                                        .StandardCopyOption
                                        .REPLACE_EXISTING
                        );
                    }
                }
            }

        } catch (Exception e) {

            response.put(
                    "status",
                    "ERROR"
            );

            response.put(
                    "message",
                    "Failed to extract extension: "
                            + e.getMessage()
            );

            return response;
        }

        // =====================================================
        // FILE INFORMATION
        // =====================================================

        String sha256Hash =
                calculateSha256(file);

        long fileSizeInBytes =
                file.getSize();

        String formattedFileSize =
                formatFileSize(
                        fileSizeInBytes
                );

        // =====================================================
        // STORE FILE IN MEMORY CACHE
        // =====================================================

        fileCache.put(
                scanId,
                fileBytes
        );

        filenameCache.put(
                scanId,
                filename
        );

        // =====================================================
        // READ MANIFEST FOR BASIC VALIDATION / EXPLANATIONS
        // =====================================================

        JsonNode manifest = null;

        String extensionName =
                "Unknown Extension";

        String extensionVersion =
                "1.0.0";

        int manifestVersion =
                3;

        List<String> extractedPermissions =
                new ArrayList<>();

        try {

            try (
                    ZipInputStream zipIn =
                            new ZipInputStream(
                                    new java.io.ByteArrayInputStream(
                                            fileBytes
                                    )
                            )
            ) {

                ZipEntry entry;

                while (
                        (entry =
                                zipIn.getNextEntry())
                                != null
                ) {

                    String entryName =
                            entry.getName()
                                    .toLowerCase();

                    if (!entry.isDirectory()
                            && (
                            entryName.endsWith(
                                    "manifest.json"
                            )
                                    || entryName.endsWith(
                                    "manifest.json.txt"
                            )
                    )) {

                        ObjectMapper mapper =
                                new ObjectMapper();

                        manifest =
                                mapper.readTree(
                                        zipIn
                                );

                        // =============================================
                        // NAME
                        // =============================================

                        if (manifest.has("name")) {

                            extensionName =
                                    manifest
                                            .get("name")
                                            .asText();
                        }

                        // =============================================
                        // VERSION
                        // =============================================

                        if (manifest.has("version")) {

                            extensionVersion =
                                    manifest
                                            .get("version")
                                            .asText();
                        }

                        // =============================================
                        // MANIFEST VERSION
                        // =============================================

                        if (manifest.has(
                                "manifest_version"
                        )) {

                            manifestVersion =
                                    manifest
                                            .get(
                                                    "manifest_version"
                                            )
                                            .asInt();
                        }

                        // =============================================
                        // PERMISSIONS
                        // =============================================

                        if (manifest.has(
                                "permissions"
                        )
                                && manifest
                                .get("permissions")
                                .isArray()) {

                            manifest
                                    .get("permissions")
                                    .forEach(
                                            permission ->
                                                    extractedPermissions
                                                            .add(
                                                                    permission
                                                                            .asText()
                                                            )
                                    );
                        }

                        // =============================================
                        // HOST PERMISSIONS
                        // =============================================

                        if (manifest.has(
                                "host_permissions"
                        )
                                && manifest
                                .get(
                                        "host_permissions"
                                )
                                .isArray()) {

                            manifest
                                    .get(
                                            "host_permissions"
                                    )
                                    .forEach(
                                            host ->
                                                    extractedPermissions
                                                            .add(
                                                                    "host: "
                                                                            + host
                                                                            .asText()
                                                            )
                                    );
                        }

                        break;
                    }
                }
            }

        } catch (Exception e) {

            response.put(
                    "status",
                    "ERROR"
            );

            response.put(
                    "message",
                    "Failed to process manifest: "
                            + e.getMessage()
            );

            return response;
        }

        // =====================================================
        // MANIFEST VALIDATION
        // =====================================================

        if (manifest == null) {

            response.put(
                    "status",
                    "ERROR"
            );

            response.put(
                    "message",
                    "manifest.json not found in extension package"
            );

            return response;
        }

        // =====================================================
        // BASIC RISK EXPLANATIONS
        // =====================================================

        for (String permission :
                extractedPermissions) {

            String normalized =
                    permission
                            .toLowerCase()
                            .trim();

            // -------------------------------------------------
            // UNIVERSAL HOST ACCESS
            // -------------------------------------------------

            if (normalized.contains(
                    "<all_urls>"
            )
                    || normalized.contains(
                    "host: *://*/*"
            )
                    || normalized.contains(
                    "host: <all_urls>"
            )) {

                appendIfMissing(
                        riskExplanations,
                        "Broad host access declared: Permits reading and altering data across all visited websites."
                );
            }

            // -------------------------------------------------
            // COOKIES
            // -------------------------------------------------

            if (normalized.equals(
                    "cookies"
            )) {

                appendIfMissing(
                        riskExplanations,
                        "Cookies access requested: Allows reading and modifying session cookies, increasing session hijacking risk."
                );
            }

            // -------------------------------------------------
            // WEB REQUEST
            // -------------------------------------------------

            if (normalized.equals(
                    "webrequest"
            )) {

                appendIfMissing(
                        riskExplanations,
                        "WebRequest API enabled: Grants capability to observe browser network activity."
                );
            }

            // -------------------------------------------------
            // WEB REQUEST BLOCKING
            // -------------------------------------------------

            if (normalized.equals(
                    "webrequestblocking"
            )) {

                appendIfMissing(
                        riskExplanations,
                        "WebRequestBlocking permission can modify network requests and represents elevated browser privilege."
                );
            }

            // -------------------------------------------------
            // SCRIPTING
            // -------------------------------------------------

            if (normalized.equals(
                    "scripting"
            )) {

                appendIfMissing(
                        riskExplanations,
                        "Scripting permission found: Allows executing scripts in permitted web pages."
                );
            }
        }

        if (riskExplanations.isEmpty()) {

            riskExplanations.add(
                    "No high-risk security behaviors or sensitive permissions identified."
            );
        }

        // =====================================================
        // IMPORTANT:
        // TASK 1 + TASK 2 + TASK 3 + TASK 4
        // ARE NOW HANDLED BY ManifestAnalysisService
        // =====================================================

        ManifestAnalysisService.AnalysisResult
                serviceResult;

        try {

            serviceResult =
                    manifestAnalysisService
                            .analyzeManifest(
                                    sandboxDir,
                                    file
                            );

        } catch (Exception e) {

            response.put(
                    "status",
                    "ERROR"
            );

            response.put(
                    "message",
                    "Manifest security analysis failed: "
                            + e.getMessage()
            );

            return response;
        }

        // =====================================================
        // GET RESULTS FROM SERVICE
        // =====================================================

        String name =
                serviceResult.getName();

        String version =
                serviceResult.getVersion();

        int analyzedManifestVersion =
                serviceResult
                        .getManifestVersion();

        List<String> permissions =
                serviceResult
                        .getPermissions();

        List<ManifestAnalysisService.PermissionFinding>
                permissionFindings =
                serviceResult
                        .getPermissionFindings();

        List<String> excessivePermissions =
                serviceResult
                        .getExcessivePermissions();

        int leastPrivilegeScore =
                serviceResult
                        .getLeastPrivilegeScore();

        int calculatedRiskScore =
                serviceResult
                        .getRiskScore();

        String versionDiff =
                serviceResult
                        .getVersionDiff();

        String sbomFindings =
                serviceResult
                        .getSbomFindings();

        String serviceHash =
                serviceResult
                        .getHash();

        // =====================================================
        // TASK 2 - REMOTE DOMAINS
        // =====================================================

        List<ManifestAnalysisService.RemoteDomainFinding>
                remoteDomains =
                manifestAnalysisService
                        .analyzeRemoteDomains(
                                manifest
                        );

        // =====================================================
        // RECOMMENDATION
        // =====================================================

        String recommendation;

        if (calculatedRiskScore > 70) {

            recommendation =
                    "BLOCK";

        } else if (calculatedRiskScore > 35) {

            recommendation =
                    "REVIEW";

        } else {

            recommendation =
                    "INSTALL";
        }

        // =====================================================
        // ANALYSIS RESPONSE
        // =====================================================

        Map<String, Object> analysis =
                new LinkedHashMap<>();

        // =====================================================
        // BASIC DETAILS
        // =====================================================

        analysis.put(
                "name",
                name
        );

        analysis.put(
                "version",
                version
        );

        analysis.put(
                "manifestVersion",
                analyzedManifestVersion
        );

        analysis.put(
                "riskScore",
                calculatedRiskScore
        );

        analysis.put(
                "permissions",
                permissions
        );

        // =====================================================
        // TASK 1 - LEAST PRIVILEGE
        // =====================================================

        analysis.put(
                "permissionFindings",
                permissionFindings
        );

        analysis.put(
                "excessivePermissions",
                excessivePermissions
        );

        analysis.put(
                "leastPrivilegeScore",
                leastPrivilegeScore
        );

        // =====================================================
        // TASK 2 - REMOTE DOMAIN INVENTORY
        // =====================================================

        analysis.put(
                "remoteDomains",
                remoteDomains
        );

        analysis.put(
                "remoteDomainCount",
                remoteDomains.size()
        );

        // =====================================================
        // TASK 4 - REAL VERSION DIFF
        // =====================================================

        /*
         * IMPORTANT:
         *
         * The controller NO LONGER creates a fake baseline.
         *
         * versionDiff comes directly from
         * ManifestAnalysisService.
         *
         * First scan:
         *
         * Initial Baseline Created
         * Version: v1.0.0
         * [=] No previous version available for comparison.
         *
         * Second scan:
         *
         * Baseline (v1.0.0) -> Target (v1.1.0)
         * [+] Added Permissions: [...]
         */

        analysis.put(
                "versionDiff",
                versionDiff
        );

        // =====================================================
        // TASK 3 - SBOM
        // =====================================================

        analysis.put(
                "sbomFindings",
                sbomFindings
        );

        // =====================================================
        // RISK EXPLANATIONS
        // =====================================================

        analysis.put(
                "riskExplanations",
                riskExplanations
        );

        // =====================================================
        // RECOMMENDATION
        // =====================================================

        analysis.put(
                "recommendation",
                recommendation
        );

        // =====================================================
        // HASH
        // =====================================================

        analysis.put(
                "hash",
                serviceHash.equals("N/A")
                        ? sha256Hash
                        : serviceHash
        );

        // =====================================================
        // FILE SIZE
        // =====================================================

        analysis.put(
                "fileSize",
                formattedFileSize
        );

        analysis.put(
                "fileSizeBytes",
                fileSizeInBytes
        );

        // =====================================================
        // ROOT RESPONSE
        // =====================================================

        response.put(
                "filename",
                filename
        );

        response.put(
                "fileSize",
                formattedFileSize
        );

        response.put(
                "fileSizeBytes",
                fileSizeInBytes
        );

        response.put(
                "status",
                calculatedRiskScore > 70
                        ? "FLAGGED"
                        : "SECURE"
        );

        response.put(
                "scanId",
                scanId
        );

        response.put(
                "sha256",
                sha256Hash
        );

        response.put(
                "hash",
                sha256Hash
        );

        response.put(
                "analysis",
                analysis
        );

        // =====================================================
        // SAVE SCAN HISTORY
        // =====================================================

        String historyExtensionName =
                name.equals(
                        "Unknown Extension"
                )
                        ? filename
                        : name;

        ScanHistory historyItem =
                new ScanHistory(
                        userEmail,
                        historyExtensionName,
                        calculatedRiskScore,
                        calculatedRiskScore > 35
                                ? "HIGH"
                                : "LOW",
                        calculatedRiskScore > 70
                                ? "FLAGGED"
                                : "SECURE",
                        LocalDateTime.now()
                );

        scanHistoryRepository.save(
                historyItem
        );

        // =====================================================
        // RETURN
        // =====================================================

        return response;
    }

    // =========================================================
    // SHA-256
    // =========================================================

    private String calculateSha256(
            MultipartFile file) {

        try {

            if (file == null
                    || file.isEmpty()) {

                return "N/A";
            }

            MessageDigest digest =
                    MessageDigest.getInstance(
                            "SHA-256"
                    );

            byte[] hashBytes =
                    digest.digest(
                            file.getBytes()
                    );

            return HexFormat
                    .of()
                    .formatHex(
                            hashBytes
                    );

        } catch (Exception e) {

            return "N/A";
        }
    }

    // =========================================================
    // FILE SIZE
    // =========================================================

    private String formatFileSize(
            long bytes) {

        if (bytes < 1024) {

            return bytes + " B";
        }

        int exp =
                (int) (
                        Math.log(bytes)
                                / Math.log(1024)
                );

        String pre =
                "KMGTPE"
                        .charAt(exp - 1)
                        + "";

        return String.format(
                "%.1f %sB",
                bytes
                        / Math.pow(
                                1024,
                                exp
                        ),
                pre
        );
    }

    // =========================================================
    // SCAN HISTORY
    // =========================================================

    @GetMapping("/scans/history")
    public ResponseEntity<List<ScanHistory>>
    getScanHistory(
            @RequestParam(
                    value = "userEmail",
                    required = false
            )
            String userEmail) {

        List<ScanHistory> history;

        if (userEmail != null
                && !userEmail.isEmpty()) {

            history =
                    scanHistoryRepository
                            .findByUserEmailOrderByIdDesc(
                                    userEmail
                            );

        } else {

            history =
                    scanHistoryRepository.findAll(
                            Sort.by(
                                    Sort.Direction.DESC,
                                    "id"
                            )
                    );
        }

        return ResponseEntity.ok(
                history
        );
    }
     // =========================================================
// AUDIT LOGS
// =========================================================

@GetMapping("/audit-logs")
public ResponseEntity<List<AuditLog>>
getAuditLogs(
        @RequestParam(
                value = "userEmail",
                required = false
        )
        String userEmail) {

    List<AuditLog> logs;

    if (userEmail != null
            && !userEmail.isEmpty()) {

        logs =
                auditLogRepository
                        .findByUserEmailOrderByIdDesc(
                                userEmail
                        );

    } else {

        logs =
                auditLogRepository.findAll(
                        Sort.by(
                                Sort.Direction.DESC,
                                "id"
                        )
                );
    }

    return ResponseEntity.ok(logs);
}
    // =========================================================
    // ALLOWLIST
    // =========================================================

    @PostMapping("/extensions/allowlist")
    public ResponseEntity<Map<String, Object>>
    allowlistExtension(
            @RequestBody(required = false)
            Map<String, String> payload) {

        String scanId =
                payload != null
                        ? payload.get("scanId")
                        : null;

        String userEmail =
                payload != null
                        ? payload.get("userEmail")
                        : null;

        String filename =
                payload != null
                        ? payload.get("filename")
                        : "extension.zip";

       if (scanId != null
        && userEmail != null) {

    allowlistedScanIds.add(
            userEmail
                    + "_"
                    + scanId
    );

    AuditLog auditLog =
            new AuditLog(
                    userEmail,
                    scanId,
                    filename,
                    "ALLOWLISTED",
                    LocalDateTime.now()
            );

    auditLogRepository.save(auditLog);
}

        Map<String, Object> result =
                new HashMap<>();

        result.put(
                "status",
                "ALLOWLISTED"
        );

        result.put(
                "message",
                "Extension "
                        + filename
                        + " has been successfully allowlisted."
        );

        return ResponseEntity.ok(
                result
        );
    }

  // =========================================================
// DOWNLOAD EXTENSION
// =========================================================

@GetMapping("/extensions/download")
public ResponseEntity<Resource> downloadExtension(
        @RequestParam(
                value = "scanId",
                required = true
        )
        String scanId) {

    if (scanId == null || scanId.isBlank()) {
        return ResponseEntity.badRequest().build();
    }

    byte[] fileBytes = fileCache.get(scanId);

    if (fileBytes == null) {
        return ResponseEntity.notFound().build();
    }

    String filename =
            filenameCache.getOrDefault(
                    scanId,
                    "extension.zip"
            );

    try {

        ByteArrayResource resource =
                new ByteArrayResource(fileBytes);

        return ResponseEntity
                .ok()
                .contentType(
                        MediaType.APPLICATION_OCTET_STREAM
                )
                .header(
                        HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"" +
                                filename +
                                "\""
                )
                .body(resource);

    } catch (Exception e) {

        return ResponseEntity
                .internalServerError()
                .build();
    }
}

   // =========================================================
// REJECT EXTENSION
// =========================================================

@PostMapping("/extensions/reject")
public ResponseEntity<Map<String, Object>>
rejectExtension(
        @RequestBody(required = false)
        Map<String, String> payload) {

    String scanId =
            payload != null
                    ? payload.get("scanId")
                    : null;

    String userEmail =
            payload != null
                    ? payload.get("userEmail")
                    : null;

    String filename =
            payload != null
                    ? payload.get("filename")
                    : "extension.zip";

    if (scanId != null
            && userEmail != null
            && !scanId.isBlank()
            && !userEmail.isBlank()) {

        AuditLog auditLog =
                new AuditLog(
                        userEmail,
                        scanId,
                        filename,
                        "REJECTED",
                        LocalDateTime.now()
                );

        auditLogRepository.save(auditLog);
    }

    Map<String, Object> result =
            new HashMap<>();

    result.put(
            "status",
            "REJECTED"
    );

    result.put(
            "message",
            "Extension "
                    + filename
                    + " has been successfully blocked and logged."
    );

    return ResponseEntity.ok(
            result
    );
}
    // =========================================================
    // DASHBOARD STATS
    // =========================================================

    @GetMapping("/extensions/stats")
    public ResponseEntity<Map<String, Object>>
    getDashboardStats(
            @RequestParam(
                    value = "userEmail",
                    required = false
            )
            String userEmail) {

        List<ScanHistory> userScans;

        if (userEmail != null
                && !userEmail.isEmpty()) {

            userScans =
                    scanHistoryRepository
                            .findByUserEmailOrderByIdDesc(
                                    userEmail
                            );

        } else {

            userScans =
                    scanHistoryRepository.findAll();
        }

        int extensionsScanned =
                userScans.size();

        long highRiskDetected =
                userScans.stream()
                        .filter(
                                s ->
                                        "HIGH".equals(
                                                s.getRiskLevel()
                                        )
                        )
                        .count();

        long userAllowlistedCount =
                allowlistedScanIds.stream()
                        .filter(
                                id ->
                                        userEmail != null
                                                && id.startsWith(
                                                userEmail
                                                        + "_"
                                        )
                        )
                        .count();

        Map<String, Object> stats =
                new HashMap<>();

        stats.put(
                "extensionsScanned",
                extensionsScanned
        );

        stats.put(
                "highRiskDetected",
                (int) highRiskDetected
        );

        stats.put(
                "avgScanTime",
                extensionsScanned > 0
                        ? "0.6s"
                        : "0.0s"
        );

        stats.put(
                "allowlisted",
                (int) userAllowlistedCount
        );

        return ResponseEntity.ok(
                stats
        );
    }

    // =========================================================
    // STORED FILE DOWNLOAD
    // =========================================================

    @GetMapping("/extensions/download-file")
    public ResponseEntity<Resource>
    downloadStoredFile(
            @RequestParam(
                    value = "filename",
                    defaultValue = "extension.zip"
            )
            String filename) {

        try {

            Path filePath =
                    fileStorageLocation
                            .resolve(filename)
                            .normalize();

            // =================================================
            // PATH TRAVERSAL PROTECTION
            // =================================================

            if (!filePath.startsWith(
                    fileStorageLocation
            )) {

                return ResponseEntity
                        .badRequest()
                        .build();
            }

            Resource resource =
                    new UrlResource(
                            filePath.toUri()
                    );

            if (!resource.exists()
                    || !resource.isReadable()) {

                return ResponseEntity
                        .notFound()
                        .build();
            }

            return ResponseEntity
                    .ok()
                    .contentType(
                            MediaType
                                    .APPLICATION_OCTET_STREAM
                    )
                    .header(
                            HttpHeaders
                                    .CONTENT_DISPOSITION,
                            "attachment; filename=\""
                                    + resource.getFilename()
                                    + "\""
                    )
                    .body(resource);

        } catch (Exception ex) {

            return ResponseEntity
                    .internalServerError()
                    .build();
        }
    }

    // =========================================================
    // HELPER
    // =========================================================

    private void appendIfMissing(
            List<String> list,
            String item) {

        if (!list.contains(item)) {

            list.add(item);
        }
    }
}