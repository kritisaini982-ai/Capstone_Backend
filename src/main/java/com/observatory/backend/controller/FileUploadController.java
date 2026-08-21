package com.observatory.backend.controller;

import com.observatory.backend.service.ManifestAnalysisService;
import com.observatory.backend.service.ManifestAnalysisService.AnalysisResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

@RestController
@RequestMapping("/api/v1/extensions")
@CrossOrigin(origins = "*")
public class FileUploadController {

    @Autowired
    private ManifestAnalysisService manifestAnalysisService;

    @PostMapping("/upload")
    public ResponseEntity<Map<String, Object>> uploadPackage(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "File is empty"));
        }

        Path tempDirPath = null;
        try {
            tempDirPath = Files.createTempDirectory("extension_scan_" + System.currentTimeMillis() + "_");
            File tempDir = tempDirPath.toFile();
            String canonicalDestinationDirPath = tempDir.getCanonicalPath();

            try (InputStream is = file.getInputStream();
                 ZipInputStream zis = new ZipInputStream(is)) {
                
                ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    File newFile = new File(tempDir, entry.getName());
                    
                    // Zip Slip Vulnerability Protection
                    String canonicalDestinationFile = newFile.getCanonicalPath();
                    if (!canonicalDestinationFile.startsWith(canonicalDestinationDirPath + File.separator)) {
                        return ResponseEntity.badRequest().body(Map.of(
                            "error", "Bad zip entry path (Zip Slip attack detected): " + entry.getName()
                        ));
                    }

                    if (entry.isDirectory()) {
                        newFile.mkdirs();
                    } else {
                        if (newFile.getParentFile() != null) {
                            newFile.getParentFile().mkdirs();
                        }
                        try (FileOutputStream fos = new FileOutputStream(newFile)) {
                            byte[] buffer = new byte[1024];
                            int len;
                            while ((len = zis.read(buffer)) > 0) {
                                fos.write(buffer, 0, len);
                            }
                        }
                    }
                    zis.closeEntry();
                }
            }

            AnalysisResult result = manifestAnalysisService.analyzeManifest(tempDir);

            Map<String, Object> analysisMap = new HashMap<>();
            analysisMap.put("name", result.getName());
            analysisMap.put("version", result.getVersion());
            analysisMap.put("manifestVersion", result.getManifestVersion());
            analysisMap.put("permissions", result.getPermissions());
            analysisMap.put("riskScore", result.getRiskScore());

            Map<String, Object> response = new HashMap<>();
            response.put("filename", file.getOriginalFilename());
            response.put("status", "EXTRACTED");
            response.put("scanId", "scan-" + System.currentTimeMillis());
            response.put("analysis", analysisMap);

            return ResponseEntity.ok(response);

        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        } finally {
            if (tempDirPath != null) {
                try (var stream = Files.walk(tempDirPath)) {
                    stream.sorted(Comparator.reverseOrder())
                          .map(Path::toFile)
                          .forEach(File::delete);
                } catch (IOException ignored) {}
            }
        }
    }
}