# console_analyzer.py
# ExeLens 1단계: 웹/DB 없이 터미널에서 PE 파일의 기본 정보만 확인하는 콘솔 분석기

import sys          # 명령줄 인자(파일 경로)를 받기 위해 사용
import pefile        # PE 파일 구조를 파싱해주는 외부 라이브러리


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