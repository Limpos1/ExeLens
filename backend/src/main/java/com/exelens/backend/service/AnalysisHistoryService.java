package com.exelens.backend.service;

import com.exelens.backend.dto.AnalysisRecordResponse;
import com.exelens.backend.dto.AnalysisResult;
import com.exelens.backend.dto.AnalysisSummary;
import com.exelens.backend.dto.ImportedLibrary;
import com.exelens.backend.dto.SectionInfo;
import com.exelens.backend.entity.AnalysisEntity;
import com.exelens.backend.entity.ImportedLibraryEntity;
import com.exelens.backend.entity.SectionEntity;
import com.exelens.backend.exception.AnalysisNotFoundException;
import com.exelens.backend.repository.AnalysisRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * 분석 결과(AnalysisResult, Python 모듈이 돌려준 것)를 DB에 저장하고,
 * 저장된 이력을 다시 꺼내서 API 응답 형태로 돌려주는 역할을 담당한다.
 *
 * PeAnalyzerService(분석 실행)와 이 서비스(이력 저장/조회)를 분리해서,
 * "분석하는 일"과 "저장/조회하는 일"이 서로 다른 책임을 갖도록 했다.
 *
 * 중복 파일 처리 정책(README 10장 4단계 항목): 지금 버전은 같은 파일(SHA-256 동일)을
 * 다시 올려도 매번 새 이력으로 저장한다. "같은 파일이면 재분석하지 않고 기존 결과를
 * 재사용한다"는 건 README 6장에 MVP 이후 확장 기능으로 분류되어 있어서, sha256 컬럼에
 * 인덱스만 걸어두고 실제 중복 방지 로직은 지금 단계에서는 구현하지 않기로 했다.
 */
@Service
public class AnalysisHistoryService {

    private final AnalysisRepository analysisRepository;

    public AnalysisHistoryService(AnalysisRepository analysisRepository) {
        this.analysisRepository = analysisRepository;
    }

    @Transactional
    public AnalysisRecordResponse save(AnalysisResult result, String originalFileName) {
        AnalysisEntity entity = new AnalysisEntity();
        entity.setOriginalFileName(originalFileName);
        entity.setSha256(result.sha256());
        entity.setPeType(result.peType());
        entity.setArchitecture(result.architecture());
        entity.setSectionCount(result.sectionCount());
        entity.setImageBase(result.imageBase());
        entity.setEntryPointRva(result.entryPointRva());
        entity.setEntryPointVa(result.entryPointVa());
        entity.setStringCount(result.stringCount());
        entity.setStringsSample(result.stringsSample());
        entity.setFindings(result.findings());

        for (SectionInfo section : result.sections()) {
            SectionEntity sectionEntity = new SectionEntity();
            sectionEntity.setName(section.name());
            sectionEntity.setVirtualSize(section.virtualSize());
            sectionEntity.setRawSize(section.rawSize());
            sectionEntity.setPermissions(section.permissions());
            sectionEntity.setWritable(section.writable());
            sectionEntity.setExecutable(section.executable());
            sectionEntity.setEntropy(section.entropy());
            entity.addSection(sectionEntity);
        }

        for (ImportedLibrary library : result.imports()) {
            ImportedLibraryEntity libraryEntity = new ImportedLibraryEntity();
            libraryEntity.setDllName(library.dll());
            libraryEntity.setFunctions(library.functions());
            entity.addImportedLibrary(libraryEntity);
        }

        AnalysisEntity saved = analysisRepository.save(entity);
        return toRecordResponse(saved);
    }

    @Transactional(readOnly = true)
    public List<AnalysisSummary> listSummaries() {
        return analysisRepository.findAllByOrderByCreatedAtDesc().stream()
                .map(entity -> new AnalysisSummary(
                        entity.getId(),
                        entity.getOriginalFileName(),
                        entity.getPeType(),
                        entity.getArchitecture(),
                        entity.getSha256(),
                        entity.getFindings().size(),
                        entity.getCreatedAt()
                ))
                .toList();
    }

    @Transactional(readOnly = true)
    public AnalysisRecordResponse getById(Long id) {
        AnalysisEntity entity = analysisRepository.findById(id)
                .orElseThrow(() -> new AnalysisNotFoundException(id));
        return toRecordResponse(entity);
    }

    private AnalysisRecordResponse toRecordResponse(AnalysisEntity entity) {
        List<SectionInfo> sections = entity.getSections().stream()
                .map(s -> new SectionInfo(
                        s.getName(), s.getVirtualSize(), s.getRawSize(),
                        s.getPermissions(), s.isWritable(), s.isExecutable(), s.getEntropy()
                ))
                .toList();

        List<ImportedLibrary> imports = entity.getImports().stream()
                .map(lib -> new ImportedLibrary(lib.getDllName(), lib.getFunctions()))
                .toList();

        return new AnalysisRecordResponse(
                entity.getId(),
                entity.getOriginalFileName(),
                entity.getCreatedAt(),
                entity.getPeType(),
                entity.getArchitecture(),
                entity.getSectionCount(),
                entity.getImageBase(),
                entity.getEntryPointRva(),
                entity.getEntryPointVa(),
                sections,
                imports,
                entity.getStringCount(),
                entity.getStringsSample(),
                entity.getSha256(),
                entity.getFindings()
        );
    }
}
