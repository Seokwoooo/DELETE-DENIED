# Suspend / Resume

두 명령 모두 현재 사용자 영역에서 실행합니다.

## 상태

- `Protected Paths: Enforced`: `~/.codex/hooks.json`에 DELETE-DENIED 훅이 등록되고 Codex가 현재 hash를 Trust한 활성 상태입니다.
- `Protected Paths: Awaiting Codex trust`: 훅은 등록됐지만 Trust가 아직 확인되지 않은 상태입니다. `delete-denied update --trust`를 다시 실행하면 명시적으로 Trust를 시도합니다.
- `Protected Paths: Suspended`: DELETE-DENIED 훅 항목만 잠시 제거된 상태입니다.

이미 열린 Codex 작업에는 즉시 반영되지 않을 수 있으므로 새 작업이나 Codex 재시작이 필요할 수
있습니다. 두 상태 모두 Full Access, sandbox, 승인 설정을 바꾸지 않습니다.

## macOS

```sh
"$HOME/.codex/delete-denied/bin/delete-denied" suspend
"$HOME/.codex/delete-denied/bin/delete-denied" status

"$HOME/.codex/delete-denied/bin/delete-denied" resume
"$HOME/.codex/delete-denied/bin/delete-denied" status
```

## Windows

```powershell
& "$env:USERPROFILE\.codex\DELETE-DENIED\bin\delete-denied.exe" suspend
& "$env:USERPROFILE\.codex\DELETE-DENIED\bin\delete-denied.exe" status

& "$env:USERPROFILE\.codex\DELETE-DENIED\bin\delete-denied.exe" resume
& "$env:USERPROFILE\.codex\DELETE-DENIED\bin\delete-denied.exe" status
```

`suspend`와 `resume`은 다른 사용자 훅을 변경하지 않습니다. `Suspended` 상태는 다시 `resume`할
때까지 유지됩니다.
