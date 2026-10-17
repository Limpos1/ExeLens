package com.exelens.backend.controller;

import com.exelens.backend.dto.AnalysisResult;
import com.exelens.backend.exception.InvalidFileException;
import com.exelens.backend.service.PeAnalyzerService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 파일 업로드를 받아서 분석 결과를 돌려주는 API.
 *
 * 흐름: 업로드된 파일 검증 -> 임시 파일로 저장 -> 분석 서비스 호출 -> 결과 반환 -> 임시 파일 삭제
 * 실제 분석 로직(Python 프로세스 호출 등)은 전부 PeAnalyzerService에 위임한다.
 */
@RestController
@RequestMapping("/api")
public class AnalysisController {

    // PE 파일은 항상 "MZ"(0x4D, 0x5A)로 시작한다. 확장자만으로는 속일 수 있으므로
    // 실제 내용의 첫 두 바이트를 확인해서 PE 파일이 아닌 게 확실한 것들을 먼저 걸러낸다.
    private static final byte[] PE_MAGIC_BYTES = {0x4D, 0x5A};

    private final PeAnalyzerService peAnalyzerService;

    public AnalysisController(PeAnalyzerService peAnalyzerService) {
        this.peAnalyzerService = peAnalyzerService;
    }

    @PostMapping("/analyze")
    public ResponseEntity<AnalysisResult> analyze(@RequestParam("file") MultipartFile file) {
        validate(file);

        Path tempFile = saveToTempFile(file);
        try {
            AnalysisResult result = peAnalyzerService.analyze(tempFile);
            return ResponseEntity.ok(result);
        } finally {
            deleteQuietly(tempFile);
        }
    }

    private void validate(MultipartFile file) {
        if (file.isEmpty()) {
            throw new InvalidFileException("파일이 비어있습니다.");
        }

        byte[] header;
        try {
            header = file.getInputStream().readNBytes(PE_MAGIC_BYTES.length);
        } catch (IOException e) {
            throw new InvalidFileException("파일을 읽을 수 없습니다.");
        }

        if (header.length < PE_MAGIC_BYTES.length
                || header[0] != PE_MAGIC_BYTES[0]
                || header[1] != PE_MAGIC_BYTES[1]) {
            throw new InvalidFileException("PE 실행 파일(MZ로 시작하는 파일)이 아닙니다.");
        }
    }

    private Path saveToTempFile(MultipartFile file) {
        try {
            Path tempFile = Files.createTempFile("exelens-upload-", ".exe");
            file.transferTo(tempFile);
            return tempFile;
        } catch (IOException e) {
            throw new UncheckedIOException("업로드된 파일을 저장하지 못했습니다.", e);
        }
    }

    private void deleteQuietly(Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {
            // 임시 파일 삭제 실패는 응답에 영향을 주지 않는다 (운영체제가 나중에 정리해도 무방).
        }
    }
}
