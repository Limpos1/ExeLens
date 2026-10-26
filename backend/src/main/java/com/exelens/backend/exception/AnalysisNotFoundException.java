package com.exelens.backend.exception;

/**
 * 조회하려는 분석 이력이 DB에 없을 때 던지는 예외. GlobalExceptionHandler가 404로 변환한다.
 */
public class AnalysisNotFoundException extends RuntimeException {

    public AnalysisNotFoundException(Long id) {
        super("해당 ID의 분석 이력을 찾을 수 없습니다: " + id);
    }
}
