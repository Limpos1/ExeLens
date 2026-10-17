package com.exelens.backend.exception;

/**
 * 파일 분석 과정에서 실패했을 때 던지는 예외.
 * - 업로드된 파일이 PE 형식이 아닐 때
 * - 분석 모듈(Python) 호출이 시간 초과되거나 비정상 종료됐을 때
 * - 분석 결과 JSON을 파싱하지 못했을 때
 * 등 "분석 자체가 불가능한" 모든 경우를 이 예외 하나로 표현한다.
 */
public class AnalysisException extends RuntimeException {

    public AnalysisException(String message) {
        super(message);
    }

    public AnalysisException(String message, Throwable cause) {
        super(message, cause);
    }
}
