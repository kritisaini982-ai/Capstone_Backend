package com.observatory.backend.service;

import org.junit.jupiter.api.Test;

import java.util.List;
import org.springframework.mock.web.MockMultipartFile;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class ManifestAnalysisServiceTest {

    private final ManifestAnalysisService service =
            new ManifestAnalysisService();

    @Test
    void shouldDetectHighRiskPermissions() {

        List<ManifestAnalysisService.PermissionFinding> findings =
                service.analyzeLeastPrivilege(
                        List.of("storage", "tabs", "cookies", "webRequest")
                );

        assertEquals(4, findings.size());

        assertEquals("LOW", findings.get(0).getSeverity());
        assertFalse(findings.get(0).isExcessive());

        assertEquals("HIGH", findings.get(1).getSeverity());
        assertTrue(findings.get(1).isExcessive());

        assertEquals("HIGH", findings.get(2).getSeverity());
        assertTrue(findings.get(2).isExcessive());

        assertEquals("HIGH", findings.get(3).getSeverity());
        assertTrue(findings.get(3).isExcessive());
    }

    @Test
    void shouldDetectUniversalHostAccessAsCritical() {

        List<ManifestAnalysisService.PermissionFinding> findings =
                service.analyzeLeastPrivilege(
                        List.of("host: *://*/*")
                );

        assertEquals(1, findings.size());
        assertEquals("CRITICAL", findings.get(0).getSeverity());
        assertTrue(findings.get(0).isExcessive());
        assertEquals("Universal Host Access",
                findings.get(0).getCategory());
    }

    @Test
    void shouldCalculateLeastPrivilegeScore() {

        List<ManifestAnalysisService.PermissionFinding> findings =
                service.analyzeLeastPrivilege(
                        List.of("storage", "tabs", "cookies")
                );

        int score =
                service.calculateLeastPrivilegeScore(findings);

        assertEquals(60, score);
    }

    @Test
    void shouldGiveFullScoreForNonExcessivePermissions() {

        List<ManifestAnalysisService.PermissionFinding> findings =
                service.analyzeLeastPrivilege(
                        List.of("storage", "activeTab")
                );

        int score =
                service.calculateLeastPrivilegeScore(findings);

        assertEquals(100, score);
    }
    @Test
    void shouldDetectAddedPermissionInVersionDiff() throws Exception {

        Path tempDir = Files.createTempDirectory("extension-diff-test");
        File sandboxDir = tempDir.toFile();

        Path manifestPath = tempDir.resolve("manifest.json");

        // Version 1.0.0 - baseline
        Files.writeString(
                manifestPath,
                """
                {
                  "name": "Version Diff Test Extension",
                  "version": "1.0.0",
                  "manifest_version": 3,
                  "permissions": ["storage"]
                }
                """
        );

        MockMultipartFile firstFile =
                new MockMultipartFile(
                        "file",
                        "extension-v1.zip",
                        "application/zip",
                        "version-one".getBytes()
                );

        ManifestAnalysisService.AnalysisResult firstResult =
                service.analyzeManifest(sandboxDir, firstFile);

        assertTrue(
                firstResult.getVersionDiff()
                        .contains("Initial Baseline Created")
        );

        // Version 1.1.0 - tabs permission added
        Files.writeString(
                manifestPath,
                """
                {
                  "name": "Version Diff Test Extension",
                  "version": "1.1.0",
                  "manifest_version": 3,
                  "permissions": ["storage", "tabs"]
                }
                """
        );

        MockMultipartFile secondFile =
                new MockMultipartFile(
                        "file",
                        "extension-v1.1.zip",
                        "application/zip",
                        "version-two".getBytes()
                );

        ManifestAnalysisService.AnalysisResult secondResult =
                service.analyzeManifest(sandboxDir, secondFile);

        assertTrue(
                secondResult.getVersionDiff()
                        .contains("tabs")
        );
    }
}