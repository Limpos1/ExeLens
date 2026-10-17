package com.exelens.backend.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * analyzer/console_analyzer.py가 "--json" 옵션으로 실행됐을 때 표준출력으로 내보내는
 * JSON 전체 구조를 그대로 옮겨 담는 자바 객체다.
 *
 * 파이썬 스크립트의 analyze_pe() 함수가 만드는 result 딕셔너리와 필드를 1:1로 맞춰뒀다.
 * (analyzer/console_analyzer.py 참고)
 */
public record AnalysisResult(
        @JsonProperty("file_path") String filePath,
        @JsonProperty("pe_type") String peType,
        String architecture,
        @JsonProperty("section_count") int sectionCount,
        @JsonProperty("image_base") String imageBase,
        @JsonProperty("entry_point_rva") String entryPointRva,
        @JsonProperty("entry_point_va") String entryPointVa,
        List<SectionInfo> sections,
        List<ImportedLibrary> imports,
        @JsonProperty("string_count") int stringCount,
        @JsonProperty("strings_sample") List<String> stringsSample,
        String sha256,
        List<String> findings
) {
}
