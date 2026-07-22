# 설치 가이드

DELETE-DENIED는 현재 사용자 영역에만 설치됩니다. Rust, Python, 별도 플러그인도 필요하지 않습니다.

## macOS

일반 터미널에서 실행하세요.

```sh
curl -fsSL https://raw.githubusercontent.com/Seokwoooo/DELETE-DENIED/main/bootstrap/install.sh | sh
```

## Windows

일반 PowerShell에서 실행하세요.

```powershell
irm https://raw.githubusercontent.com/Seokwoooo/DELETE-DENIED/main/bootstrap/install.ps1 | iex
```

## 설치기가 하는 일

1. GitHub의 최신 안정 릴리스에서 현재 OS와 CPU에 맞는 압축 파일을 받습니다.
2. 설치기 내부에서 공개된 `SHA256SUMS`와 다운로드 파일의 SHA-256을 비교합니다.
3. 실행 파일과 정책을 현재 사용자의 `.codex/delete-denied` 아래에 복사합니다.
4. 기존 `~/.codex/hooks.json`을 보존하면서 DELETE-DENIED `PreToolUse` 항목만 추가합니다.
5. 기존 훅 파일이 있으면 `backups/hooks.json.before-install`에 한 번 백업합니다.
6. 기존 `config.toml`이 있으면 `backups/config.toml.before-trust`에 한 번 보관합니다.
7. Codex app-server의 `hooks/list`로 설치한 handler의 identity를 확인하고, 일치하는 항목만
   `config/batchWrite`로 Trust한 뒤 다시 검증합니다.
8. 마지막으로 DELETE-DENIED 자체 `doctor`를 실행해 등록과 활성화 상태를 확인합니다.
   등록이 정상이면 `registration: ok`를 출력합니다.

설치 경로는 다음과 같습니다.

| OS | CLI | 관리 파일 | Codex 훅 |
| --- | --- | --- | --- |
| macOS | `~/.codex/delete-denied/bin/delete-denied` | `~/.codex/delete-denied/` | `~/.codex/hooks.json` |
| Windows | `%USERPROFILE%\.codex\DELETE-DENIED\bin\delete-denied.exe` | `%USERPROFILE%\.codex\DELETE-DENIED\` | `%USERPROFILE%\.codex\hooks.json` |

## 상태와 업데이트

정상 활성 상태는 `Protected Paths: Enforced`와 `activation: Codex trust ok`입니다. 훅이
비활성화되거나 hash가 바뀌면 `status`와 `doctor`가 해당 상태를 표시합니다. 일반 `install`은
등록만 하고 `Protected Paths: Awaiting Codex trust`를 유지하며, 명시적인 `install --trust` 또는 `update --trust`만
app-server Trust 절차를 실행합니다. app-server를 사용할 수 없거나 identity가 정확히 하나가
아니면 config를 쓰지 않고 실패합니다.

macOS:

```sh
"$HOME/.codex/delete-denied/bin/delete-denied" status
"$HOME/.codex/delete-denied/bin/delete-denied" doctor
```

Windows:

```powershell
& "$env:USERPROFILE\.codex\DELETE-DENIED\bin\delete-denied.exe" status
& "$env:USERPROFILE\.codex\DELETE-DENIED\bin\delete-denied.exe" doctor
```

업데이트는 처음과 같은 한 줄 설치 명령을 다시 실행하면 됩니다.

## 제거

macOS:

```sh
"$HOME/.codex/delete-denied/bin/delete-denied" uninstall
```

Windows:

```powershell
& "$env:USERPROFILE\.codex\DELETE-DENIED\bin\delete-denied.exe" uninstall
```

제거는 `hooks.json`의 DELETE-DENIED 항목과 DELETE-DENIED 사용자 폴더만 삭제합니다. 다른
사용자 훅과 Codex 설정은 유지합니다.
