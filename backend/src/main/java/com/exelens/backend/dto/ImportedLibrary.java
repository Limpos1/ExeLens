package com.exelens.backend.dto;

import java.util.List;

/**
 * Python 분석 모듈이 돌려주는 JSON의 "imports" 배열 항목 하나에 대응한다.
 * 하나의 DLL과, 그 DLL에서 가져오는 함수 이름 목록을 담는다.
 */
public record ImportedLibrary(
        String dll,
        List<String> functions
) {
}
