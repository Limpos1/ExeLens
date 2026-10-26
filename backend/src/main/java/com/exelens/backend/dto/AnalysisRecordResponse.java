package com.exelens.backend.dto;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 분석 결과 상세 응답. AnalysisResult(분석 모듈이 돌려준 원본 결과)에
 * DB 저장 이후 생기는 정보(id, 원본 파일명, 저장 시각)를 더한 형태다.
 *
 * POST /api/analyze (방금 분석한 결과) 와 GET /api/analyses/{id} (저장된 이력 조회)
 * 두 API가 같은 모양의 응답을 돌려주도록 이 타입 하나로 통일했다.
 */
public record AnalysisRecordResponse(
        Long id,
        String originalFileName,
        LocalDateTime createdAt,
        String peType,
        String architecture,
        int sectionCount,
        String imageBase,
        String entryPointRva,
        String entryPointVa,
        List<SectionInfo> sections,
        List<ImportedLibrary> imports,
        int stringCount,
        List<String> stringsSample,
        String sha256,
        List<String> findings
) {
}
