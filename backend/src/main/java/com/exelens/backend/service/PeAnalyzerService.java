package com.exelens.backend.service;

import com.exelens.backend.dto.AnalysisResult;
import com.exelens.backend.exception.AnalysisException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

/**
 * Python 분석 모듈(console_analyzer.py)을 별도 프로세스로 실행하고,
 * 그 결과(JSON)를 받아와 자바 객체로 변환하는 역할을 담당한다.
 *
 * 컨트롤러는 "파일을 받아서 검증하는 일"만 하고, 실제 분석 호출은
 * 이 서비스에 위임한다 (역할 분리).
 */
@Service
public class PeAnalyzerService {

    private final String pythonExecutable;
    private final String scriptPath;
    private final long timeoutSeconds;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public PeAnalyzerService(
            @Value("${exelens.analyzer.python-executable}") String pythonExecutable,
            @Value("${exelens.analyzer.script-path}") String scriptPath,
            @Value("${exelens.analyzer.timeout-seconds}") long timeoutSeconds
    ) {
        this.pythonExecutable = pythonExecutable;
        this.scriptPath = scriptPath;
        this.timeoutSeconds = timeoutSeconds;
    }

    /**
     * 주어진 경로의 파일을 분석 모듈로 분석해서 결과를 돌려준다.
     * 분석에 실패하면(PE가 아니거나, 스크립트 실행 자체가 실패하면) AnalysisException을 던진다.
     */
    public AnalysisResult analyze(Path targetFile) {
        ProcessBuilder processBuilder = new ProcessBuilder(
                pythonExecutable, scriptPath, targetFile.toString(), "--json"
        );

        Process process;
        try {
            process = processBuilder.start();
        } catch (IOException e) {
            // python 실행 파일을 못 찾는 경우 등, 프로세스 시작 자체가 안 된 경우
            throw new AnalysisException("분석 프로세스를 시작할 수 없습니다: " + e.getMessage(), e);
        }

        String stdout;
        String stderr;
        boolean finishedInTime;
        try {
            stdout = readAll(process.getInputStream());
            stderr = readAll(process.getErrorStream());
            finishedInTime = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
        } catch (IOException | InterruptedException e) {
            process.destroyForcibly();
            Thread.currentThread().interrupt();
            throw new AnalysisException("분석 결과를 읽는 중 오류가 발생했습니다: " + e.getMessage(), e);
        }

        if (!finishedInTime) {
            process.destroyForcibly();
            throw new AnalysisException("분석이 " + timeoutSeconds + "초 안에 끝나지 않아 중단했습니다.");
        }

        if (process.exitValue() != 0) {
            // console_analyzer.py가 실패했을 때는 {"error": "..."} 형태를 stderr로 보낸다.
            String message = extractErrorMessage(stderr);
            throw new AnalysisException(message);
        }

        try {
            return objectMapper.readValue(stdout, AnalysisResult.class);
        } catch (IOException e) {
            throw new AnalysisException("분석 결과(JSON)를 해석하지 못했습니다.", e);
        }
    }

    private String readAll(InputStream inputStream) throws IOException {
        return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
    }

    private String extractErrorMessage(String stderr) {
        try {
            var errorNode = objectMapper.readTree(stderr);
            if (errorNode.has("error")) {
                return errorNode.get("error").asText();
            }
        } catch (IOException ignored) {
            // stderr가 JSON이 아니면(예상 못한 예외 등) 원문을 그대로 보여준다.
        }
        return stderr.isBlank() ? "알 수 없는 이유로 분석에 실패했습니다." : stderr.trim();
    }
}
