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
import com.observatory.backend.service.JwtService;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

@RestController
@RequestMapping("/api/v1")
@CrossOrigin(origins = "${APP_FRONTEND_URL:http://localhost:3000}")
public class FileUploadController {

    @Autowired
    private ScanHistoryRepository scanHistoryRepository;

    @Autowired
    private UserRepository userRepository;

    private final PasswordEncoder passwordEncoder =
            new BCryptPasswordEncoder();

    @Autowired
    private JwtService jwtService;

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

    // Stores which authenticated user owns each scan
    private final Map<String, String> scanOwnerCache =
            new ConcurrentHashMap<>();

    // Maps authenticated user + filename to that user's latest scan
    private final Map<String, String> userFilenameScanCache =
            new ConcurrentHashMap<>();

    // =========================================================
    // ALLOWLIST CACHE
    // =========================================================

    private final Set<String> allowlistedScanIds =
            ConcurrentHashMap.newKeySet();

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

            response.put(
                    "message",
                    "Email and password are required"
            );

            return ResponseEntity
                    .badRequest()
                    .body(response);
        }

        if (password.length() < 8) {

            response.put(
                    "message",
                    "Password must be at least 8 characters long"
            );

            return ResponseEntity
                    .badRequest()
                    .body(response);
        }

        Optional<User> userOpt =
                userRepository.findByEmail(email);

        if (userOpt.isPresent()) {

            User user = userOpt.get();

            String storedPassword =
                    user.getPassword();

            boolean valid = false;

            // =================================================
            // BCrypt password
            // =================================================

            if (storedPassword != null
                    && (
                    storedPassword.startsWith("$2a$")
                            || storedPassword.startsWith("$2b$")
                            || storedPassword.startsWith("$2y$")
            )) {

                valid =
                        passwordEncoder.matches(
                                password,
                                storedPassword
                        );

            } else {

                // =================================================
                // Existing plaintext password migration
                // =================================================

                valid =
                        storedPassword != null
                                && storedPassword.equals(password);

                if (valid) {

                    user.setPassword(
                            passwordEncoder.encode(password)
                    );

                    userRepository.save(user);
                }
            }

            // =================================================
            // LOGIN SUCCESS
            // =================================================

            if (valid) {

                response.put(
                        "token",
                        jwtService.generateToken(email)
                );

                response.put(
                        "message",
                        "Login successful"
                );

                return ResponseEntity.ok(response);
            }
        }

        // =================================================
        // LOGIN FAILED
        // =================================================

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

        if (password.length() < 8) {

            response.put(
                    "message",
                    "Password must be at least 8 characters long"
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

        // =================================================
        // STORE BCrypt HASH
        // =================================================

        String hashedPassword =
                passwordEncoder.encode(password);

        userRepository.save(
                new User(
                        email,
                        hashedPassword
                )
        );

        // =================================================
        // GENERATE JWT
        // =================================================

        response.put(
                "token",
                jwtService.generateToken(email)
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
            String userEmail,
            HttpServletRequest request) {

        // =====================================================
        // USE JWT IDENTITY - NEVER TRUST REQUEST userEmail
        // =====================================================

        String authenticatedEmail =
                getAuthenticatedEmail(request);

        Map<String, Object> response =
                new HashMap<>();

        if (authenticatedEmail == null
                || authenticatedEmail.isBlank()) {

            response.put(
                    "status",
                    "ERROR"
            );

            response.put(
                    "message",
                    "Authenticated user identity is missing"
            );

            return response;
        }

        // Use authenticated JWT email from this point onward
        userEmail = authenticatedEmail;

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
        // MAXIMUM UPLOAD SIZE - 20 MB
        // =====================================================

        long maxFileSize =
                20L * 1024 * 1024;

        if (file.getSize() > maxFileSize) {

            response.put(
                    "status",
                    "ERROR"
            );

            response.put(
                    "message",
                    "Extension file exceeds the maximum allowed size of 20 MB"
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
                                java.nio.file.StandardCopyOption
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

        scanOwnerCache.put(
                scanId,
                authenticatedEmail
        );

        // Map this user's filename to their latest scan
        String userFilenameKey =
                authenticatedEmail
                        + "::"
                        + filename;

        userFilenameScanCache.put(
                userFilenameKey,
                scanId
        );

        // =====================================================
        // READ MANIFEST
        // =====================================================

        JsonNode manifest = null;

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
        // SECURITY ANALYSIS
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
        // GET RESULTS
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
        // REMOTE DOMAINS
        // =====================================================

        List<ManifestAnalysisService.RemoteDomainFinding>
                remoteDomains =
                serviceResult
                        .getRemoteDomains();

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
        // LEAST PRIVILEGE
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
        // REMOTE DOMAIN INVENTORY
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
        // VERSION DIFF
        // =====================================================

        analysis.put(
                "versionDiff",
                versionDiff
        );

        // =====================================================
        // SBOM
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
                        authenticatedEmail,
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
            String userEmail,
            HttpServletRequest request) {

        String authenticatedEmail =
                getAuthenticatedEmail(request);

        if (authenticatedEmail == null
                || authenticatedEmail.isBlank()) {

            return ResponseEntity
                    .status(401)
                    .build();
        }

        List<ScanHistory> history =
                scanHistoryRepository
                        .findByUserEmailOrderByIdDesc(
                                authenticatedEmail
                        );

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
            String userEmail,
            HttpServletRequest request) {

        String authenticatedEmail =
                getAuthenticatedEmail(request);

        if (authenticatedEmail == null
                || authenticatedEmail.isBlank()) {

            return ResponseEntity
                    .status(401)
                    .build();
        }

        List<AuditLog> logs =
                auditLogRepository
                        .findByUserEmailOrderByIdDesc(
                                authenticatedEmail
                        );

        return ResponseEntity.ok(
                logs
        );
    }

    // =========================================================
    // ALLOWLIST
    // =========================================================

    @PostMapping("/extensions/allowlist")
    public ResponseEntity<Map<String, Object>>
    allowlistExtension(
            @RequestBody(required = false)
            Map<String, String> payload,
            HttpServletRequest request) {

        String scanId =
                payload != null
                        ? payload.get("scanId")
                        : null;

        String filename =
                payload != null
                        ? payload.get("filename")
                        : "extension.zip";

        String authenticatedEmail =
                getAuthenticatedEmail(request);

        Map<String, Object> result =
                new HashMap<>();

        if (authenticatedEmail == null
                || authenticatedEmail.isBlank()) {

            result.put(
                    "status",
                    "ERROR"
            );

            result.put(
                    "message",
                    "Authenticated user identity is missing"
            );

            return ResponseEntity
                    .status(401)
                    .body(result);
        }

        if (scanId == null || scanId.isBlank()) {

            result.put(
                    "status",
                    "ERROR"
            );

            result.put(
                    "message",
                    "Scan ID is required"
            );

            return ResponseEntity
                    .badRequest()
                    .body(result);
        }

        // =====================================================
        // VERIFY SCAN OWNERSHIP
        // =====================================================

        String ownerEmail =
                scanOwnerCache.get(scanId);

        if (ownerEmail == null
                || !authenticatedEmail.equals(ownerEmail)) {

            result.put(
                    "status",
                    "ERROR"
            );

            result.put(
                    "message",
                    "You are not authorized to allowlist this scan"
            );

            return ResponseEntity
                    .status(403)
                    .body(result);
        }

        allowlistedScanIds.add(
                authenticatedEmail
                        + "_"
                        + scanId
        );

        AuditLog auditLog =
                new AuditLog(
                        authenticatedEmail,
                        scanId,
                        filename,
                        "ALLOWLISTED",
                        LocalDateTime.now()
                );

        auditLogRepository.save(
                auditLog
        );

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
    public ResponseEntity<Resource>
    downloadExtension(
            @RequestParam(
                    value = "scanId",
                    required = true
            )
            String scanId,
            HttpServletRequest request) {

        if (scanId == null || scanId.isBlank()) {

            return ResponseEntity
                    .badRequest()
                    .build();
        }

        String authenticatedEmail =
                getAuthenticatedEmail(request);

        if (authenticatedEmail == null
                || authenticatedEmail.isBlank()) {

            return ResponseEntity
                    .status(401)
                    .build();
        }

        String ownerEmail =
                scanOwnerCache.get(scanId);

        if (ownerEmail == null
                || !authenticatedEmail.equals(ownerEmail)) {

            return ResponseEntity
                    .status(403)
                    .build();
        }

        byte[] fileBytes =
                fileCache.get(scanId);

        if (fileBytes == null) {

            return ResponseEntity
                    .notFound()
                    .build();
        }

        String filename =
                filenameCache.getOrDefault(
                        scanId,
                        "extension.zip"
                );

        try {

            ByteArrayResource resource =
                    new ByteArrayResource(
                            fileBytes
                    );

            return ResponseEntity
                    .ok()
                    .contentType(
                            MediaType.APPLICATION_OCTET_STREAM
                    )
                    .header(
                            HttpHeaders.CONTENT_DISPOSITION,
                            "attachment; filename=\""
                                    + filename
                                    + "\""
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
            Map<String, String> payload,
            HttpServletRequest request) {

        String scanId =
                payload != null
                        ? payload.get("scanId")
                        : null;

        String filename =
                payload != null
                        ? payload.get("filename")
                        : "extension.zip";

        String authenticatedEmail =
                getAuthenticatedEmail(request);

        Map<String, Object> result =
                new HashMap<>();

        if (authenticatedEmail == null
                || authenticatedEmail.isBlank()) {

            result.put(
                    "status",
                    "ERROR"
            );

            result.put(
                    "message",
                    "Authenticated user identity is missing"
            );

            return ResponseEntity
                    .status(401)
                    .body(result);
        }

        if (scanId == null || scanId.isBlank()) {

            result.put(
                    "status",
                    "ERROR"
            );

            result.put(
                    "message",
                    "Scan ID is required"
            );

            return ResponseEntity
                    .badRequest()
                    .body(result);
        }

        // =====================================================
        // VERIFY SCAN OWNERSHIP
        // =====================================================

        String ownerEmail =
                scanOwnerCache.get(scanId);

        if (ownerEmail == null
                || !authenticatedEmail.equals(ownerEmail)) {

            result.put(
                    "status",
                    "ERROR"
            );

            result.put(
                    "message",
                    "You are not authorized to reject this scan"
            );

            return ResponseEntity
                    .status(403)
                    .body(result);
        }

        AuditLog auditLog =
                new AuditLog(
                        authenticatedEmail,
                        scanId,
                        filename,
                        "REJECTED",
                        LocalDateTime.now()
                );

        auditLogRepository.save(
                auditLog
        );

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
            String userEmail,
            HttpServletRequest request) {

        String authenticatedEmail =
                getAuthenticatedEmail(request);

        Map<String, Object> stats =
                new HashMap<>();

        if (authenticatedEmail == null
                || authenticatedEmail.isBlank()) {

            stats.put(
                    "status",
                    "ERROR"
            );

            stats.put(
                    "message",
                    "Authenticated user identity is missing"
            );

            return ResponseEntity
                    .status(401)
                    .body(stats);
        }

        List<ScanHistory> userScans =
                scanHistoryRepository
                        .findByUserEmailOrderByIdDesc(
                                authenticatedEmail
                        );

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

        final String finalAuthenticatedEmail =
                authenticatedEmail;

        long userAllowlistedCount =
                allowlistedScanIds.stream()
                        .filter(
                                id ->
                                        id.startsWith(
                                                finalAuthenticatedEmail
                                                        + "_"
                                        )
                        )
                        .count();

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
            String filename,
            HttpServletRequest request) {

        // =====================================================
        // GET AUTHENTICATED USER
        // =====================================================

        String authenticatedEmail =
                getAuthenticatedEmail(request);

        if (authenticatedEmail == null
                || authenticatedEmail.isBlank()) {

            return ResponseEntity
                    .status(401)
                    .build();
        }

        // =====================================================
        // VALIDATE FILENAME
        // =====================================================

        if (filename == null
                || filename.isBlank()) {

            return ResponseEntity
                    .badRequest()
                    .build();
        }

        // =====================================================
        // FIND THIS USER'S OWN SCAN
        // =====================================================

        String userFilenameKey =
                authenticatedEmail
                        + "::"
                        + filename;

        String scanId =
                userFilenameScanCache.get(
                        userFilenameKey
                );

        if (scanId == null
                || scanId.isBlank()) {

            return ResponseEntity
                    .notFound()
                    .build();
        }

        // =====================================================
        // VERIFY SCAN OWNERSHIP
        // =====================================================

        String ownerEmail =
                scanOwnerCache.get(scanId);

        if (ownerEmail == null
                || !authenticatedEmail.equals(ownerEmail)) {

            return ResponseEntity
                    .status(403)
                    .build();
        }

        // =====================================================
        // GET CACHED FILE
        // =====================================================

        byte[] fileBytes =
                fileCache.get(scanId);

        if (fileBytes == null) {

            return ResponseEntity
                    .notFound()
                    .build();
        }

        String storedFilename =
                filenameCache.getOrDefault(
                        scanId,
                        filename
                );

        // =====================================================
        // RETURN FILE
        // =====================================================

        ByteArrayResource resource =
                new ByteArrayResource(
                        fileBytes
                );

        return ResponseEntity
                .ok()
                .contentType(
                        MediaType.APPLICATION_OCTET_STREAM
                )
                .header(
                        HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\""
                                + storedFilename
                                + "\""
                )
                .body(resource);
    }

    // =========================================================
    // AUTHENTICATED USER HELPER
    // =========================================================

    private String getAuthenticatedEmail(
            HttpServletRequest request) {

        Object email =
                request.getAttribute(
                        "authenticatedEmail"
                );

        return email != null
                ? email.toString()
                : null;
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