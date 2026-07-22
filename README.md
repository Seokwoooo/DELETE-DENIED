[한국어](README.md) | [English](README.en.md) | [日本語](README.ja.md)

# DELETE-DENIED

> AI가 지우기 전에, DELETE-DENIED.

DELETE-DENIED는 Codex가 중요한 로컬 부모 폴더를 지우려 할 때 한 번 더 확인하도록 만든
안전장치입니다. Claude Code는 현재 지원하지 않습니다.

## 빠른 설치 (권장)

아래 한 줄을 Codex 메인 세션에 그대로 보내세요.

```text
DELETE-DENIED를 설치해. README의 현재 OS용 한 줄 명령을 바로 실행해: https://github.com/Seokwoooo/DELETE-DENIED
```

---

## 수동 설치

macOS에서 설치 (일반 터미널)

```sh
curl -fsSL https://raw.githubusercontent.com/Seokwoooo/DELETE-DENIED/main/bootstrap/install.sh | sh
```

Windows에서 설치 (일반 PowerShell)

```powershell
irm https://raw.githubusercontent.com/Seokwoooo/DELETE-DENIED/main/bootstrap/install.ps1 | iex
```

설치기는 최신 릴리스를 내려받아 SHA-256을 확인하고 `--trust` 설치 또는 업데이트를
수행합니다. 이 과정은 Codex app-server를 통해 정확한 DELETE-DENIED hook만 신뢰하고,
마지막에는 자체 `doctor`로 등록과 활성화 상태를 확인합니다. app-server를 사용할 수 없으면
신뢰 쓰기 없이 짧게 실패합니다. 다시 실행하면 최신 릴리스로 업데이트합니다.
macOS와 Windows 모두 현재 사용자의 `~/.codex` 아래에만 씁니다.

## 대기 중 CPU·RAM 사용량 0

호출 사이에는 DELETE-DENIED 프로세스가 남아 있지 않습니다. Codex가 `^Bash$`에
맞는 터미널 도구를 호출할 때마다 짧은 검사 프로세스가 한 번 시작되고, 안전한 명령은
정책 파일을 읽기 전에 끝납니다.

## 원리: Codex의 훅을 사용합니다

훅은 Codex가 도구를 사용하기 직전이나 사용한 뒤에 정해진 검사를 끼워 넣을 수 있는
공식 기능입니다. DELETE-DENIED는 실행 전 단계인 `PreToolUse`에 연결됩니다.

1. Codex가 `Bash` 도구로 터미널 명령을 준비합니다.
2. `PreToolUse` 훅이 실행 직전에 작은 검사 프로그램을 한 번 호출합니다.
3. 안전한 명령은 정책 파일을 읽지 않고 바로 통과합니다.
4. 삭제 후보일 때만 실제 위치를 기준으로 대상 경로를 확인하고 보호 경로와 비교합니다.
5. 중요한 상위 폴더를 지우려는 명령에는 거부 응답을 반환하도록 설계하고 정상적인 프로젝트 작업은 허용합니다.
6. 검사가 끝나면 프로세스도 종료됩니다.

도구 이름 matcher가 `^Bash$`이므로 삭제 명령뿐 아니라 일치하는 모든 Bash 호출에서
짧은 검사가 한 번 실행됩니다. 폴더를 계속 훑거나 파일 변경을 상시 관찰하는 방식이
아닙니다.

## 무엇을 보호하나요?

제품 범위는 Codex의 `PreToolUse` `Bash` 훅으로 전달되는 터미널 삭제 호출입니다. 검사기는 중요한 로컬 부모
경로를 대상으로 한 위험한 삭제에 거부 응답을 반환하도록 설계되었습니다. OS 전체의 삭제
차단기는 아니며, Codex의 다른 파일 변경 방식, 화면이나 파일 관리 앱을 직접 조작하는 작업,
브라우저 다운로드, 원격·클라우드·데이터베이스 작업, 다른 프로그램과 다른 AI 도구는 범위
밖입니다. 자세한 포함·제외 범위는 [보호 범위와 한계](docs/threat-model.md)를 참조하세요.

## 자세한 문서

- [설치 가이드](docs/install.md) — 설치, 업데이트, 제거 절차
- [중지·재개 안내](docs/suspend-resume.md) — 보호 상태를 안전하게 바꾸는 방법
- [작동 원리](docs/architecture.md) — 훅과 명령이 동작하는 방식
- [보호 범위와 한계](docs/threat-model.md) — 보호되는 작업과 보호되지 않는 작업
- [조사 근거](docs/research.md) — 제품의 근거와 참고 자료

## 라이선스와 보안 제보

DELETE-DENIED는 MIT License로 배포합니다. 보안 취약점은 [SECURITY.md](SECURITY.md)의
안내에 따라 제보해 주세요.
