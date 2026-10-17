# console_analyzer.py
# ExeLens 2단계: PE 파일의 헤더, 섹션, Import, 문자열, 해시를 분석하고
#               규칙 기반 주의 요소를 탐지한 뒤 JSON으로 결과를 출력하는 콘솔 분석기

import sys
import re
import json
import hashlib
import pefile

MIN_STRING_LENGTH = 4          # 이보다 짧은 문자열은 노이즈로 보고 제외한다
HIGH_ENTROPY_THRESHOLD = 7.5   # 이 값 이상이면 패킹/암호화 가능성으로 본다
SUSPICIOUS_IMPORTS = {
    # 디버거 탐지/회피에 흔히 쓰이는 함수들
    "IsDebuggerPresent": "디버거 탐지 시도 (안티 디버깅)",
    "CheckRemoteDebuggerPresent": "디버거 탐지 시도 (안티 디버깅)",
    "OutputDebugStringW": "디버거 탐지 우회 기법에 사용되기도 함",
    # 프로세스 인젝션(다른 프로세스에 코드 주입)에 흔히 쓰이는 함수들
    "CreateRemoteThread": "프로세스 인젝션에 사용될 수 있는 함수",
    "WriteProcessMemory": "다른 프로세스 메모리 조작에 사용될 수 있는 함수",
    "VirtualAllocEx": "다른 프로세스에 메모리 할당 시 사용되는 함수",
    "SetWindowsHookExW": "키로깅 등에 사용될 수 있는 후킹 함수",
}


def get_pe_type(pe: pefile.PE) -> str:
    """OPTIONAL_HEADER.Magic 값으로 PE32 / PE32+ 를 구분한다."""
    magic = pe.OPTIONAL_HEADER.Magic
    if magic == 0x10B:
        return "PE32"
    if magic == 0x20B:
        return "PE32+"
    return "알 수 없음"


def get_architecture(pe: pefile.PE) -> str:
    """FILE_HEADER.Machine 값으로 CPU 아키텍처를 구분한다."""
    machine = pe.FILE_HEADER.Machine
    if machine == 0x14C:
        return "x86 (32비트)"
    if machine == 0x8664:
        return "x64 (64비트)"
    return f"기타 (0x{machine:X})"


def get_section_info(pe: pefile.PE) -> list:
    """각 섹션의 이름, 크기, 권한, 엔트로피를 리스트로 모은다."""
    sections = []
    for section in pe.sections:
        name = section.Name.decode(errors="ignore").rstrip("\x00")

        is_readable = bool(section.Characteristics & 0x40000000)
        is_writable = bool(section.Characteristics & 0x80000000)
        is_executable = bool(section.Characteristics & 0x20000000)

        permissions = ""
        permissions += "R" if is_readable else "-"
        permissions += "W" if is_writable else "-"
        permissions += "X" if is_executable else "-"

        sections.append({
            "name": name,
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "permissions": permissions,
            "writable": is_writable,
            "executable": is_executable,
            "entropy": round(section.get_entropy(), 2),
        })
    return sections


def get_imports(pe: pefile.PE) -> list:
    """Import DLL과 각 DLL에서 가져오는 함수 목록을 모은다."""
    imports = []
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imports

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode(errors="ignore")
        functions = []
        for imported_func in entry.imports:
            if imported_func.name is not None:
                functions.append(imported_func.name.decode(errors="ignore"))
            else:
                functions.append(f"(ordinal {imported_func.ordinal})")
        imports.append({"dll": dll_name, "functions": functions})
    return imports


def get_strings(pe: pefile.PE) -> list:
    """파일 전체 바이트에서 출력 가능한 아스키 문자열을 추출한다."""
    pattern = rb"[\x20-\x7e]{%d,}" % MIN_STRING_LENGTH
    found = re.findall(pattern, pe.__data__)
    return [s.decode(errors="ignore") for s in found]


def get_sha256(pe: pefile.PE) -> str:
    """파일 전체 바이트의 SHA-256 해시값을 계산한다."""
    return hashlib.sha256(pe.__data__).hexdigest()


def find_suspicious_indicators(sections: list, imports: list) -> list:
    """
    지금까지 모은 정보를 규칙 기반으로 훑어서 "주의 요소"를 찾아낸다.
    백신처럼 확정 판단을 내리는 게 아니라, 사람이 더 살펴볼 만한 힌트를 모으는 것이다.
    """
    findings = []

    # 규칙 1: 쓰기와 실행이 동시에 가능한 섹션 (RWX)은 흔치 않은 패턴이다.
    for section in sections:
        if section["writable"] and section["executable"]:
            findings.append(
                f"[주의] 섹션 '{section['name']}'이 쓰기+실행 권한(RWX)을 동시에 가짐 "
                f"- 코드가 실행 중 스스로를 수정할 수 있는 구조"
            )

    # 규칙 2: 엔트로피가 비정상적으로 높은 섹션은 패킹/암호화 가능성이 있다.
    for section in sections:
        if section["entropy"] >= HIGH_ENTROPY_THRESHOLD:
            findings.append(
                f"[주의] 섹션 '{section['name']}'의 엔트로피가 {section['entropy']} "
                f"로 높음 (패킹 또는 암호화 가능성)"
            )

    # 규칙 3: 주의가 필요한 API를 가져다 쓰는지 확인한다.
    for dll_entry in imports:
        for func_name in dll_entry["functions"]:
            if func_name in SUSPICIOUS_IMPORTS:
                findings.append(
                    f"[주의] {dll_entry['dll']}의 '{func_name}' 함수 사용 "
                    f"- {SUSPICIOUS_IMPORTS[func_name]}"
                )

    return findings


def analyze_pe(file_path: str) -> dict | None:
    """
    주어진 경로의 파일을 PE 구조로 열어서 전체 정보를 분석하고,
    결과를 담은 딕셔너리를 돌려준다. PE가 아니면 None을 돌려준다.
    """
    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError:
        print("이 파일은 올바른 PE 파일이 아닙니다.")
        return None
    except FileNotFoundError:
        print(f"파일을 찾을 수 없습니다: {file_path}")
        return None

    entry_point_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    image_base = pe.OPTIONAL_HEADER.ImageBase

    sections = get_section_info(pe)
    imports = get_imports(pe)
    strings = get_strings(pe)
    findings = find_suspicious_indicators(sections, imports)

    result = {
        "file_path": file_path,
        "pe_type": get_pe_type(pe),
        "architecture": get_architecture(pe),
        "section_count": pe.FILE_HEADER.NumberOfSections,
        "image_base": hex(image_base),
        "entry_point_rva": hex(entry_point_rva),
        "entry_point_va": hex(image_base + entry_point_rva),
        "sections": sections,
        "imports": imports,
        "string_count": len(strings),
        "strings_sample": strings[:20],
        "sha256": get_sha256(pe),
        "findings": findings,
    }

    pe.close()
    return result


def print_human_readable(result: dict) -> None:
    """결과 딕셔너리를 사람이 읽기 좋은 형태로 터미널에 출력한다."""
    print("=" * 40)
    print(f"파일 경로       : {result['file_path']}")
    print(f"PE 형식         : {result['pe_type']}")
    print(f"아키텍처        : {result['architecture']}")
    print(f"섹션 개수       : {result['section_count']}")
    print(f"이미지 베이스   : {result['image_base']}")
    print(f"진입점 (RVA)    : {result['entry_point_rva']}")
    print(f"진입점 (실주소) : {result['entry_point_va']}")

    print("\n[섹션 상세 정보]")
    for section in result["sections"]:
        print(f"  {section['name']:<10} "
              f"가상크기: 0x{section['virtual_size']:X}  "
              f"실제크기: 0x{section['raw_size']:X}  "
              f"권한: {section['permissions']}  "
              f"엔트로피: {section['entropy']}")

    print("\n[Import DLL 목록]")
    if result["imports"]:
        for entry in result["imports"]:
            print(f"  {entry['dll']}")
            for func_name in entry["functions"]:
                print(f"      - {func_name}")
    else:
        print("  Import 정보가 없습니다.")

    print(f"\n[문자열 추출] (총 {result['string_count']}개 중 앞 20개만 출력)")
    for s in result["strings_sample"]:
        print(f"  {s}")

    print(f"\nSHA-256          : {result['sha256']}")

    print("\n[규칙 기반 주의 요소]")
    if result["findings"]:
        for finding in result["findings"]:
            print(f"  {finding}")
    else:
        print("  특별히 발견된 주의 요소가 없습니다.")

    print("=" * 40)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("사용법: python console_analyzer.py <분석할 exe 파일 경로>")
        sys.exit(1)

    target_file = sys.argv[1]
    analysis_result = analyze_pe(target_file)

    if analysis_result is not None:
        print_human_readable(analysis_result)

        # 사람이 보는 출력과는 별도로, 나중에 Spring Boot와 연동할 때 쓸
        # JSON 결과를 analysis_result.json 파일로 저장해둔다.
        with open("analysis_result.json", "w", encoding="utf-8") as f:
            json.dump(analysis_result, f, ensure_ascii=False, indent=2)
        print("\n(분석 결과가 analysis_result.json 파일로 저장되었습니다.)")
