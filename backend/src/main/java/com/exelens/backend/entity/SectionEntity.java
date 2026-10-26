package com.exelens.backend.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

/**
 * README 9장의 "SectionAnalysis" 모델에 대응한다.
 * 하나의 Analysis(분석 1건)는 여러 개의 섹션을 가진다 (.text, .data, .rdata 등).
 */
@Entity
@Table(name = "section")
public class SectionEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "analysis_id")
    private AnalysisEntity analysis;

    private String name;
    private long virtualSize;
    private long rawSize;
    private String permissions;
    private boolean writable;
    private boolean executable;
    private double entropy;

    public Long getId() {
        return id;
    }

    public AnalysisEntity getAnalysis() {
        return analysis;
    }

    public void setAnalysis(AnalysisEntity analysis) {
        this.analysis = analysis;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public long getVirtualSize() {
        return virtualSize;
    }

    public void setVirtualSize(long virtualSize) {
        this.virtualSize = virtualSize;
    }

    public long getRawSize() {
        return rawSize;
    }

    public void setRawSize(long rawSize) {
        this.rawSize = rawSize;
    }

    public String getPermissions() {
        return permissions;
    }

    public void setPermissions(String permissions) {
        this.permissions = permissions;
    }

    public boolean isWritable() {
        return writable;
    }

    public void setWritable(boolean writable) {
        this.writable = writable;
    }

    public boolean isExecutable() {
        return executable;
    }

    public void setExecutable(boolean executable) {
        this.executable = executable;
    }

    public double getEntropy() {
        return entropy;
    }

    public void setEntropy(double entropy) {
        this.entropy = entropy;
    }
}
