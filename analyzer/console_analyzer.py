# console_analyzer.py
# ExeLens 1단계: 웹/DB 없이 터미널에서 PE 파일의 기본 정보만 확인하는 콘솔 분석기

import sys          # 명령줄 인자(파일 경로)를 받기 위해 사용
import pefile        # PE 파일 구조를 파싱해주는 외부 라이브러리
import hashlib


def analyze_pe(file_path: str) -> None:
    """
    주어진 경로의 파일을 PE 구조로 열어서
    기본 정보(형식, 아키텍처, 섹션 개수, 진입점)를 출력한다.
    """

    # 1) 파일을 PE 형식으로 열어본다.
    #    PE가 아닌 파일이거나 손상된 파일이면 pefile이 예외(에러)를 던진다.
    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError:
        # 확장자만 .exe여도 실제 내용이 PE가 아닐 수 있으므로
        # 예외를 잡아서 "PE 파일이 아닙니다" 라고 명확히 알려준다.
        print("이 파일은 올바른 PE 파일이 아닙니다.")
        return
    except FileNotFoundError:
        print(f"파일을 찾을 수 없습니다: {file_path}")
        return

    # 2) PE32 인지 PE32+(64비트) 인지 확인한다.
    #    OPTIONAL_HEADER.Magic 값으로 구분한다.
    #    0x10b = PE32 (32비트), 0x20b = PE32+ (64비트)
    magic = pe.OPTIONAL_HEADER.Magic
    if magic == 0x10B:
        pe_type = "PE32"
    elif magic == 0x20B:
        pe_type = "PE32+"
    else:
        pe_type = "알 수 없음"

    # 3) 아키텍처(x86 / x64)를 확인한다.
    #    FILE_HEADER.Machine 값으로 CPU 종류를 구분한다.
    machine = pe.FILE_HEADER.Machine
    if machine == 0x14C:
        architecture = "x86 (32비트)"
    elif machine == 0x8664:
        architecture = "x64 (64비트)"
    else:
        architecture = f"기타 (0x{machine:X})"

    # 4) 섹션 개수는 FILE_HEADER.NumberOfSections에 바로 들어있다.
    section_count = pe.FILE_HEADER.NumberOfSections

    # 5) 진입점(프로그램이 실행을 시작하는 주소)은
    #    OPTIONAL_HEADER.AddressOfEntryPoint 에 들어있다.
    #    실제 메모리 주소를 보려면 ImageBase를 더해야 하므로 같이 계산한다.
    entry_point_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    image_base = pe.OPTIONAL_HEADER.ImageBase
    entry_point_va = image_base + entry_point_rva

    # 6) 지금까지 구한 정보를 보기 좋게 출력한다.

    print("=" * 40)
    print(f"파일 경로       : {file_path}")
    print(f"PE 형식         : {pe_type}")
    print(f"아키텍처        : {architecture}")
    print(f"섹션 개수       : {section_count}")
    print(f"이미지 베이스   : 0x{image_base:X}")
    print(f"진입점 (RVA)    : 0x{entry_point_rva:X}")
    print(f"진입점 (실주소) : 0x{entry_point_va:X}")
    
        # 7) 각 섹션의 상세 정보를 확인한다.
    #    섹션은 실행 파일 안에서 코드/데이터가 실제로 저장되는 블록 단위이다.
    #    예: .text(코드), .data(전역 변수), .rdata(읽기전용 데이터) 등
    print("\n[섹션 상세 정보]")
    for section in pe.sections:
        # 섹션 이름은 null 바이트로 채워진 고정 길이 바이트열이라 디코딩 후 제거해줘야 한다.
        name = section.Name.decode(errors="ignore").rstrip("\x00")

        # Characteristics 값은 여러 권한 비트를 하나의 정수에 담고 있다.
        # 각 비트를 AND 연산으로 검사해서 읽기/쓰기/실행 여부를 판단한다.
        is_readable = bool(section.Characteristics & 0x40000000)
        is_writable = bool(section.Characteristics & 0x80000000)
        is_executable = bool(section.Characteristics & 0x20000000)

        permissions = ""
        permissions += "R" if is_readable else "-"
        permissions += "W" if is_writable else "-"
        permissions += "X" if is_executable else "-"

        entropy = section.get_entropy()

        print(f"  {name:<10} 가상크기: 0x{section.Misc_VirtualSize:X}  "
              f"실제크기: 0x{section.SizeOfRawData:X}  권한: {permissions}"
            f"엔트로피: {entropy:.2f}")

            # 8) 이 파일이 가져다 쓰는 DLL과 함수 목록을 확인한다 (Import Table).
    #    pefile은 import 정보가 있을 때만 DIRECTORY_ENTRY_IMPORT 속성을 만들어준다.
    #    (DLL 같은 일부 파일은 import가 없을 수도 있어서 hasattr로 먼저 확인한다.)
    print("\n[Import DLL 목록]")
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            # DLL 이름도 bytes라서 decode 해준다.
            dll_name = entry.dll.decode(errors="ignore")
            print(f"  {dll_name}")

            # 각 DLL에서 가져오는 함수들을 하나씩 출력한다.
            for imported_func in entry.imports:
                # 함수를 이름이 아니라 번호(ordinal)로만 가져오는 경우도 있어서
                # name이 None일 수 있다. 그럴 땐 번호를 대신 보여준다.
                if imported_func.name is not None:
                    func_name = imported_func.name.decode(errors="ignore")
                else:
                    func_name = f"(ordinal {imported_func.ordinal})"
                print(f"      - {func_name}")
    else:
        print("  Import 정보가 없습니다.")

        # 9) 파일 안에 박혀있는 읽을 수 있는 문자열을 추출한다.
    #    pe.__data__ 에는 pefile이 파일을 열 때 읽어둔 전체 바이트가 그대로 들어있다.
    #    (파일을 다시 열 필요 없이 이미 메모리에 있는 걸 재사용하는 것)
    import re

    MIN_STRING_LENGTH = 4  # 너무 짧은 건 의미 없는 문자열일 가능성이 높아서 제외

    # 정규식 설명:
    #   [\x20-\x7e] -> 공백(0x20)부터 ~ (0x7e) 사이, 즉 "출력 가능한 아스키 문자" 하나
    #   {4,}        -> 그런 문자가 4개 이상 연속으로 나타나는 부분을 찾는다
    pattern = rb"[\x20-\x7e]{%d,}" % MIN_STRING_LENGTH
    found_strings = re.findall(pattern, pe.__data__)

    print(f"\n[문자열 추출] (총 {len(found_strings)}개 중 앞 20개만 출력)")
    for s in found_strings[:20]:
        # 여기서도 bytes이므로 decode 해서 사람이 읽을 수 있는 문자열로 바꾼다.
        print(f"  {s.decode(errors='ignore')}")

    sha256_hash = hashlib.sha256(pe.__data__).hexdigest()
    print(f"\nSHA-256          : {sha256_hash}")
    
    print("=" * 40)

    # 다 쓴 PE 객체는 명시적으로 닫아준다 (파일 핸들 정리).
    pe.close()


if __name__ == "__main__":
    # 스크립트를 "python console_analyzer.py 파일경로" 형태로 실행하는지 확인
    if len(sys.argv) != 2:
        print("사용법: python console_analyzer.py <분석할 exe 파일 경로>")
        sys.exit(1)

    target_file = sys.argv[1]
    analyze_pe(target_file)