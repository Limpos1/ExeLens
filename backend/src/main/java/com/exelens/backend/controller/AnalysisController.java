package com.exelens.backend.controller;

import com.exelens.backend.dto.AnalysisRecordResponse;
import com.exelens.backend.dto.AnalysisResult;
import com.exelens.backend.dto.AnalysisSummary;
import com.exelens.backend.exception.InvalidFileException;
import com.exelens.backend.service.AnalysisHistoryService;
import com.exelens.backend.service.PeAnalyzerService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * 파일 업로드 -> 분석 -> 저장 -> 조회까지 담당하는 API.
 *
 * 흐름: 업로드된 파일 검증 -> 임시 파일로 저장 -> 분석 서비스 호출
 *       -> 이력 저장 서비스에 결과 저장 -> 저장된 결과 반환 -> 임시 파일 삭제
 *
 * 역할 분리:
 * - PeAnalyzerService    : Python 분석 모듈을 호출해서 "분석 결과"를 얻어오는 일만 한다.
 * - AnalysisHistoryService: 분석 결과를 DB에 "저장"하고, 저장된 이력을 "조회"하는 일만 한다.
 * - AnalysisController   : 요청을 받아서 위 두 서비스에 순서대로 일을 시키고, 응답을 만든다.
 */
@RestController
@RequestMapping("/api")
public class AnalysisController {

    // PE 파일은 항상 "MZ"(0x4D, 0x5A)로 시작한다. 확장자만으로는 속일 수 있으므로
    // 실제 내용의 첫 두 바이트를 확인해서 PE 파일이 아닌 게 확실한 것들을 먼저 걸러낸다.
    private static final byte[] PE_MAGIC_BYTES = {0x4D, 0x5A};

    private final PeAnalyzerService peAnalyzerService;
    private final AnalysisHistoryService analysisHistoryService;

    public AnalysisController(PeAnalyzerService peAnalyzerService,
                               AnalysisHistoryService analysisHistoryService) {
        this.peAnalyzerService = peAnalyzerService;
        this.analysisHistoryService = analysisHistoryService;
    }

    @PostMapping("/analyze")
    public ResponseEntity<AnalysisRecordResponse> analyze(@RequestParam("file") MultipartFile file) {
        validate(file);

        Path tempFile = saveToTempFile(file);
        try {
            AnalysisResult result = peAnalyzerService.analyze(tempFile);
            AnalysisRecordResponse saved = analysisHistoryService.save(result, file.getOriginalFilename());
            return ResponseEntity.ok(saved);
        } finally {
            deleteQuietly(tempFile);
        }
    }

    @GetMapping("/analyses")
    public ResponseEntity<List<AnalysisSummary>> listAnalyses() {
        return ResponseEntity.ok(analysisHistoryService.listSummaries());
    }

    @GetMapping("/analyses/{id}")
    public ResponseEntity<AnalysisRecordResponse> getAnalysis(@PathVariable Long id) {
        return ResponseEntity.ok(analysisHistoryService.getById(id));
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
