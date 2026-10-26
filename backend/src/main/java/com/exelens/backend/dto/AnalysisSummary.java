package com.exelens.backend.dto;

import java.time.LocalDateTime;

/**
 * GET /api/analyses (분석 이력 목록) 응답에 쓰는 요약 정보.
 * 섹션/Import/문자열 같은 무거운 데이터는 빼고, 목록 화면에 필요한 정보만 담았다.
 * 상세 정보가 필요하면 GET /api/analyses/{id}로 따로 조회한다.
 */
public record AnalysisSummary(
        Long id,
        String originalFileName,
        String peType,
        String architecture,
        String sha256,
        int findingCount,
        LocalDateTime createdAt
) {
}
