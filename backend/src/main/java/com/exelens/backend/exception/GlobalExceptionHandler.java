package com.exelens.backend.exception;

import com.exelens.backend.dto.ErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

/**
 * 컨트롤러 어디서든 예외가 던져지면 이곳에서 한 곳에 모아 처리한다.
 * 컨트롤러 코드 안에 try-catch를 흩뿌리지 않고, "어떤 예외는 어떤 HTTP 상태로 응답한다"는
 * 규칙을 한 파일에서 관리하기 위한 것이다 (Spring의 @RestControllerAdvice 기능).
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    // 요청 자체가 잘못된 경우 (파일이 비어있음, PE 파일이 아님 등) -> 400 Bad Request
    @ExceptionHandler(InvalidFileException.class)
    public ResponseEntity<ErrorResponse> handleInvalidFile(InvalidFileException e) {
        return ResponseEntity.badRequest().body(new ErrorResponse(e.getMessage()));
    }

    // 업로드 용량 제한 초과 -> 413 Payload Too Large
    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<ErrorResponse> handleMaxUploadSize(MaxUploadSizeExceededException e) {
        return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
                .body(new ErrorResponse("업로드 가능한 파일 크기를 초과했습니다."));
    }

    // 요청은 정상이지만 분석 자체가 실패한 경우 -> 422 Unprocessable Entity
    @ExceptionHandler(AnalysisException.class)
    public ResponseEntity<ErrorResponse> handleAnalysisError(AnalysisException e) {
        log.warn("분석 실패: {}", e.getMessage());
        return ResponseEntity.unprocessableEntity().body(new ErrorResponse(e.getMessage()));
    }

    // 예상하지 못한 나머지 모든 예외 -> 500 Internal Server Error
    // (내부 오류의 자세한 내용을 클라이언트에 그대로 노출하지 않고, 서버 로그에만 남긴다)
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleUnexpected(Exception e) {
        log.error("예상하지 못한 오류", e);
        return ResponseEntity.internalServerError()
                .body(new ErrorResponse("서버에서 알 수 없는 오류가 발생했습니다."));
    }
}
