# DELETE-DENIED 조사 근거

조사 기준일: 2026-07-18 (KST)

이 문서는 공개 자료, OpenAI 공식 문서, 이 저장소에 체크인된 측정 자료를 나눠 기록합니다. `확인됨`은 원문이나 로컬 증거에서 직접 확인한 사실입니다. `제품 해석`은 그 사실을 바탕으로 정한 설계입니다. `미확인`은 공개 자료만으로 결론을 내릴 수 없는 항목입니다.

## 확인됨

### 실제 사고에 대해 공개된 사실

- Matt Shumer는 [X 게시물](https://x.com/mattshumer_/status/2075657271401390161)에서 GPT-5.6-Sol이 자신의 Mac 파일을 거의 모두 삭제했다고 보고했습니다. 첨부 화면에 공개된 명령은 정확히 `rm -rf /Users/mattsdevbox`입니다.
- `/Users/mattsdevbox`가 macOS 사용자 home처럼 보인다는 해석은 경로 형식에 따른 것입니다. 공개 자료는 이 경로가 전체 디스크 루트 `/`라고 말하지 않습니다.
- OpenAI 엔지니어 Thibault Sottiaux는 [별도의 X 설명](https://x.com/thsottiaux/status/2077630111499882637)에서 조사한 소수의 파일 삭제 보고와 Full Access, sandbox 보호가 적용되지 않은 조건, `$HOME`을 임시 폴더로 다루려다 실제 home을 가리키게 된 실수를 설명했습니다. 이 글은 Matt의 전체 실행 로그나 독립적인 포렌식 보고서가 아니라 사건 맥락을 설명하는 공개 발언입니다.
- [GPT-5.6 System Card](https://deploymentsafety.openai.com/gpt-5-6)는 사용자가 지정한 VM과 다른 VM을 정리한 사례, 허위 완료 보고, 승인되지 않은 credential 복사 사례를 별도로 기록합니다. 이 사례들은 Matt의 Mac 사고에 대한 명령이나 피해 목록이 아닙니다.

### Codex 공식 문서에서 확인된 것

- [Codex Hooks](https://developers.openai.com/codex/hooks)는 `PreToolUse` matcher가 `tool_name`에 적용되고, `^Bash$`처럼 도구 이름을 지정할 수 있으며, `permissionDecision = "deny"` 형식의 구조화된 응답을 사용할 수 있다고 설명합니다.
- Codex의 훅 Trust 상태는 `config.toml`의 handler별 hash와 enabled 값으로 관리되므로, DELETE-DENIED는 등록만으로 활성이라고 표시하지 않고 현재 hash가 Trust된 경우에만 `Protected Paths: Enforced`로 표시합니다.
- 현재 설치기의 명시적인 `--trust` 경로는 `codex app-server --stdio`에 JSON-RPC `initialize`와 `initialized`를 보낸 뒤 `hooks/list`의 exact handler identity를 확인하고, 일치하는 key 하나에만 `config/batchWrite`를 적용한 다음 다시 `hooks/list`로 `trusted`와 `enabled`를 확인합니다. 이 저장소의 protocol 테스트가 이 흐름과 실패 시 무기록 동작을 검증합니다.
- 같은 문서는 `PreToolUse`가 완전한 실행 차단 경계가 아니라 guardrail이라고 설명하고, 모든 shell 호출을 가로채지 못할 수 있으며 `unified_exec` 같은 경로의 interception이 불완전할 수 있다고 적습니다. hook이 지원하지 않는 출력 필드를 반환하면 Codex가 오류를 보고한 뒤 tool call을 계속할 수 있다는 설명도 있습니다. timeout과 일반 비정상 종료의 모든 경우를 설명한 문서는 아닙니다.
- [Auto-review 문서](https://developers.openai.com/codex/sandboxing/auto-review)는 sandbox에서 사람의 승인을 reviewer agent로 바꾸는 기능을 설명합니다. auto-review가 DELETE-DENIED의 hook이나 파일 경로 정책을 대신하는 기능이라는 내용은 없습니다.

### 버전과 저장소 자료

- 공식 [Codex CLI 0.124.0 release](https://github.com/openai/codex/releases/tag/rust-v0.124.0)는 hooks가 stable이라고 기록합니다. 이는 CLI release 자료이지 Codex App의 최소 버전을 정한 자료가 아닙니다.
- [Codex App 소개 글](https://openai.com/index/introducing-the-codex-app/)은 macOS 앱 소개와 이후 Windows 제공을 알립니다. hooks를 지원하는 App의 공식 숫자 버전이나 최소 버전은 이 자료에서 확인되지 않습니다.

## 제품 해석

- 공개된 정확한 명령이 POSIX shell 형태이므로 첫 보호 경계를 Codex의 네이티브 Bash hook으로 좁혔습니다. 명령 문자열만 보고 Codex 내부 handler를 이름 붙이지 않습니다.
- 중요한 부모 경로와 현재 workspace의 조상을 보호하고, 그 아래의 구체적인 프로젝트 하위 경로는 허용하는 것이 정상적인 개발 작업과 사고 예방을 함께 다루는 가장 작은 범위라고 판단했습니다.
- 검사 엔진은 POSIX, PowerShell, Windows `cmd`, 제한된 Node.js·Python inline 문법을 읽을 수 있습니다. 이 능력은 입력이 hook으로 전달되었을 때의 parser 범위일 뿐, Codex App의 모든 실행 표면을 지원한다는 의미가 아닙니다.
- hook matcher가 명령 내용이 아닌 `Bash` 도구 이름에 붙으므로 Bash 호출마다 짧은 검사가 한 번 실행됩니다. 검사 사이에 daemon이나 polling 프로세스를 두지 않는 이유도 여기에 있습니다.
- `Protected Paths: Suspended`는 현재 작업의 권한을 자동으로 넓히지 않고 사용자 훅 항목만 잠시 제거한 상태입니다. 다시 켤 때까지 유지됩니다.

## 미확인

다음 질문은 현재 공개 자료와 체크인된 증거만으로 답할 수 없습니다.

- Matt Shumer 사고가 Codex 내부에서 정확히 어떤 tool handler(`Bash`, `unified_exec` 등)를 거쳤는지
- 삭제된 파일의 완전한 목록, 개수, 복구율, 백업 상태와 전체 피해·복구 과정
- Codex App의 공식 hooks 지원 최소 버전과 OS별 전체 지원 매트릭스
- 현재 release가 실제 Codex App의 live `Bash` 호출을 훅으로 전달하고, deny 응답 뒤 실행을 막는 end-to-end 결과
- hook timeout, 실행 파일 crash, 잘못된 출력 뒤 Codex가 해당 tool call을 중지하는지에 대한 모든 버전별 동작
- Codex가 hook 밖으로 보내는 전체 로컬 변경 표면
- 경로 검사와 OS 작업 사이의 TOCTOU 경쟁을 운영체제 수준에서 없앨 수 있는지

따라서 README와 제품 설명은 “모든 삭제를 막는다”가 아니라, **지원 범위 안에서 hook으로 전달된 Codex Bash 호출의 중요 부모 경로 삭제를 검사하도록 설계했다**고만 말해야 합니다. 실제 보호 범위와 제외 범위는 [보호 범위와 한계](threat-model.md), 훅 흐름은 [작동 원리](architecture.md)에 각각 정리되어 있습니다.
