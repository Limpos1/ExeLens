package com.exelens.backend.entity;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OrderColumn;
import jakarta.persistence.Table;

import java.util.ArrayList;
import java.util.List;

/**
 * README 9장의 "ImportedLibrary" 모델에 대응한다.
 * 하나의 Analysis는 여러 DLL을 가져다 쓰고, 각 DLL은 여러 함수를 가져다 쓴다.
 *
 * README 9장은 ImportedFunction을 별도 엔티티로 두고 있지만, 함수 하나하나를
 * 독립적으로 조회/검색할 필요가 지금은 없어서 문자열 목록(@ElementCollection)으로
 * 단순화했다. 나중에 "함수명으로 분석 이력 검색" 같은 기능이 필요해지면
 * 그때 별도 엔티티로 승격하면 된다.
 */
@Entity
@Table(name = "imported_library")
public class ImportedLibraryEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "analysis_id")
    private AnalysisEntity analysis;

    private String dllName;

    @ElementCollection
    @CollectionTable(name = "imported_function", joinColumns = @JoinColumn(name = "library_id"))
    @Column(name = "name", length = 500)
    @OrderColumn(name = "function_order")
    private List<String> functions = new ArrayList<>();

    public Long getId() {
        return id;
    }

    public AnalysisEntity getAnalysis() {
        return analysis;
    }

    public void setAnalysis(AnalysisEntity analysis) {
        this.analysis = analysis;
    }

    public String getDllName() {
        return dllName;
    }

    public void setDllName(String dllName) {
        this.dllName = dllName;
    }

    public List<String> getFunctions() {
        return functions;
    }

    public void setFunctions(List<String> functions) {
        this.functions = functions;
    }
}
