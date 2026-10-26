package com.exelens.backend.entity;

import jakarta.persistence.CascadeType;
import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OrderColumn;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * 분석 1건에 대한 기록을 담는 엔티티. README 9장의 "Analysis" 모델에 대응한다.
 *
 * 섹션(SectionEntity)과 Import DLL(ImportedLibraryEntity)은 별도 테이블로 분리하고,
 * ImportedFunction은 ImportedLibraryEntity 안에 문자열 목록으로 단순화해서 담았다
 * (함수 하나하나를 따로 조회할 일이 당장은 없어서, 테이블을 하나 더 늘리는 대신 단순화했다).
 *
 * 문자열(ExtractedString)은 README 9장에 적힌 대로 "전체를 다 저장할 필요가 있는지" 검토한 결과,
 * 지금은 상위 20개 샘플과 전체 개수만 저장하기로 했다 (분석 모듈의 JSON과 동일한 수준).
 */
@Entity
@Table(name = "analysis", indexes = {
        @Index(name = "idx_analysis_sha256", columnList = "sha256")
})
public class AnalysisEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String originalFileName;

    @Column(length = 64)
    private String sha256;

    private String peType;
    private String architecture;
    private int sectionCount;
    private String imageBase;
    private String entryPointRva;
    private String entryPointVa;
    private int stringCount;

    private LocalDateTime createdAt;

    @OneToMany(mappedBy = "analysis", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @OrderColumn(name = "section_order")
    private List<SectionEntity> sections = new ArrayList<>();

    @OneToMany(mappedBy = "analysis", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @OrderColumn(name = "library_order")
    private List<ImportedLibraryEntity> imports = new ArrayList<>();

    @ElementCollection
    @CollectionTable(name = "analysis_strings_sample", joinColumns = @jakarta.persistence.JoinColumn(name = "analysis_id"))
    @Column(name = "content", length = 1000)
    @OrderColumn(name = "string_order")
    private List<String> stringsSample = new ArrayList<>();

    @ElementCollection
    @CollectionTable(name = "analysis_findings", joinColumns = @jakarta.persistence.JoinColumn(name = "analysis_id"))
    @Column(name = "content", length = 1000)
    @OrderColumn(name = "finding_order")
    private List<String> findings = new ArrayList<>();

    @PrePersist
    void onCreate() {
        this.createdAt = LocalDateTime.now();
    }

    // --- getter / setter ---
    // (JPA 엔티티는 값을 읽고 쓸 수 있어야 해서 getter/setter를 직접 열어둔다. Lombok 없이 손으로 작성.)

    public Long getId() {
        return id;
    }

    public String getOriginalFileName() {
        return originalFileName;
    }

    public void setOriginalFileName(String originalFileName) {
        this.originalFileName = originalFileName;
    }

    public String getSha256() {
        return sha256;
    }

    public void setSha256(String sha256) {
        this.sha256 = sha256;
    }

    public String getPeType() {
        return peType;
    }

    public void setPeType(String peType) {
        this.peType = peType;
    }

    public String getArchitecture() {
        return architecture;
    }

    public void setArchitecture(String architecture) {
        this.architecture = architecture;
    }

    public int getSectionCount() {
        return sectionCount;
    }

    public void setSectionCount(int sectionCount) {
        this.sectionCount = sectionCount;
    }

    public String getImageBase() {
        return imageBase;
    }

    public void setImageBase(String imageBase) {
        this.imageBase = imageBase;
    }

    public String getEntryPointRva() {
        return entryPointRva;
    }

    public void setEntryPointRva(String entryPointRva) {
        this.entryPointRva = entryPointRva;
    }

    public String getEntryPointVa() {
        return entryPointVa;
    }

    public void setEntryPointVa(String entryPointVa) {
        this.entryPointVa = entryPointVa;
    }

    public int getStringCount() {
        return stringCount;
    }

    public void setStringCount(int stringCount) {
        this.stringCount = stringCount;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public List<SectionEntity> getSections() {
        return sections;
    }

    public List<ImportedLibraryEntity> getImports() {
        return imports;
    }

    public List<String> getStringsSample() {
        return stringsSample;
    }

    public void setStringsSample(List<String> stringsSample) {
        this.stringsSample = stringsSample;
    }

    public List<String> getFindings() {
        return findings;
    }

    public void setFindings(List<String> findings) {
        this.findings = findings;
    }

    /** 연관관계 편의 메서드: 섹션을 추가하면서 양쪽(Analysis <-> Section) 참조를 동시에 맞춰준다. */
    public void addSection(SectionEntity section) {
        section.setAnalysis(this);
        this.sections.add(section);
    }

    /** 연관관계 편의 메서드: Import DLL을 추가하면서 양쪽 참조를 동시에 맞춰준다. */
    public void addImportedLibrary(ImportedLibraryEntity library) {
        library.setAnalysis(this);
        this.imports.add(library);
    }
}
