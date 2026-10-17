package com.exelens.backend.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Python 분석 모듈이 돌려주는 JSON의 "sections" 배열 항목 하나에 대응한다.
 * 필드 이름은 파이썬 쪽 JSON 키(snake_case)를 자바 컨벤션(camelCase)으로 옮긴 것이다.
 */
public record SectionInfo(
        String name,
        @JsonProperty("virtual_size") long virtualSize,
        @JsonProperty("raw_size") long rawSize,
        String permissions,
        boolean writable,
        boolean executable,
        double entropy
) {
}
