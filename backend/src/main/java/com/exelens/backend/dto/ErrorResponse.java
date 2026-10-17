package com.exelens.backend.dto;

/**
 * 오류가 발생했을 때 클라이언트(프론트엔드)에게 돌려주는 공통 응답 형태.
 * 성공 응답(AnalysisResult)과 모양이 달라서, 프론트엔드는 HTTP 상태 코드로
 * "성공인지 실패인지"를 먼저 구분하고, 실패라면 이 형태로 메시지를 읽는다.
 */
public record ErrorResponse(String error) {
}
