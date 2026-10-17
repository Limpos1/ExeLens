package com.exelens.backend.exception;

/**
 * 업로드된 파일 자체가 요청 형식에 맞지 않을 때 던지는 예외.
 * (파일이 비어있음, PE 파일이 아닌 게 확실한 경우 등 - 분석을 시도하기도 전에 걸러내는 검증 단계)
 *
 * AnalysisException과 구분하는 이유: 이건 "요청이 잘못됐다"(400)는 의미이고,
 * AnalysisException은 "요청은 정상인데 분석이 실패했다"(422)는 의미라서 HTTP 상태 코드가 다르다.
 */
public class InvalidFileException extends RuntimeException {

    public InvalidFileException(String message) {
        super(message);
    }
}
