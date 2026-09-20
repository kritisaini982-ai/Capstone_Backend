package com.observatory.backend.model;

import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "audit_logs")
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String userEmail;

    @Column(nullable = false)
    private String scanId;

    @Column(nullable = false)
    private String extensionName;

    @Column(nullable = false)
    private String decision;

    @Column(nullable = false)
    private LocalDateTime timestamp;

    public AuditLog() {
    }

    public AuditLog(
            String userEmail,
            String scanId,
            String extensionName,
            String decision,
            LocalDateTime timestamp
    ) {
        this.userEmail = userEmail;
        this.scanId = scanId;
        this.extensionName = extensionName;
        this.decision = decision;
        this.timestamp = timestamp;
    }

    public Long getId() {
        return id;
    }

    public String getUserEmail() {
        return userEmail;
    }

    public String getScanId() {
        return scanId;
    }

    public String getExtensionName() {
        return extensionName;
    }

    public String getDecision() {
        return decision;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public void setUserEmail(String userEmail) {
        this.userEmail = userEmail;
    }

    public void setScanId(String scanId) {
        this.scanId = scanId;
    }

    public void setExtensionName(String extensionName) {
        this.extensionName = extensionName;
    }

    public void setDecision(String decision) {
        this.decision = decision;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }
}