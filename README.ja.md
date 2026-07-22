[한국어](README.md) | [English](README.en.md) | [日本語](README.ja.md)

# DELETE-DENIED

> AIが削除する前に、DELETE-DENIED。

DELETE-DENIEDは、Codexが大切なローカル親フォルダーを削除しようとしたときに、もう一度
確認できるようにする安全ガードです。Claude Codeには現在対応していません。

## インストール

macOSのターミナルで次の1行を実行します。

```sh
curl -fsSL https://raw.githubusercontent.com/Seokwoooo/DELETE-DENIED/main/bootstrap/install.sh | sh
```

Windowsでは通常のPowerShellで実行します。

```powershell
irm https://raw.githubusercontent.com/Seokwoooo/DELETE-DENIED/main/bootstrap/install.ps1 | iex
```

インストーラーは最新リリースを取得し、SHA-256を確認してTrust付きのインストールまたは更新を
行います。Codex app-server経由でDELETE-DENIED自身のフックだけをTrustし、最後に`doctor`で
登録と有効化状態を確認します。app-serverが使えない場合はTrust状態を書き込まず短時間で失敗します。
同じコマンドを再実行すると更新されます。

macOSとWindowsのどちらでも、現在のユーザーの`.codex`配下にだけインストールします。

## 待機中のCPU・RAM使用量は0

呼び出しの間にDELETE-DENIEDのプロセスは残りません。Codexが`^Bash$`に一致する
ターミナルツールを呼び出すたびに短いチェックが1回だけ始まり、安全なコマンドはポリシー
ファイルを読む前に終了します。

## 仕組み: Codexのフックを使います

フックとは、Codexがツールを使う直前または直後に、決められた検査を差し込める公式機能です。
DELETE-DENIEDは実行前の`PreToolUse`イベントに接続します。

1. Codexが`Bash`ツール用のターミナルコマンドを準備します。
2. `PreToolUse`フックが実行直前に小さな検査プログラムを1回呼び出します。
3. 安全なコマンドはポリシーファイルを読まずに通過します。
4. 削除候補の場合だけ対象パスを実際の場所に基づいて解決し、保護パスと比較します。
5. 重要な親フォルダーの削除には拒否応答を返すよう設計し、通常のプロジェクト作業は許可します。
6. 検査が終わるとプロセスも終了します。

ツール名のmatcherが`^Bash$`なので、削除コマンドだけでなく一致するすべてのBash呼び出しで
短いチェックが1回実行されます。フォルダーを継続的に調べたり、ファイルの変化を追いかけ
続けたりする仕組みではありません。

## 何を保護し、何を保護しないか

製品の対象は、Codexの`PreToolUse` `Bash`フックへ渡されるターミナル削除呼び出しです。
検査プログラムは重要なローカル親パスへの危険な削除を拒否するよう設計
されています。OS全体の削除ブロッカーではありません。Codexの他のファイル変更方法、画面や
ファイルマネージャーの直接操作、ブラウザのダウンロード、リモート・クラウド・データベースの
作業、他のプログラムや他のAIツールは対象外です。詳しい境界は[保護範囲と制限（韓国語）](docs/threat-model.md)を
ご覧ください。

## 詳細ドキュメント

- [インストールガイド（韓国語）](docs/install.md) — インストール、更新、削除
- [一時停止・再開ガイド（韓国語）](docs/suspend-resume.md) — 保護状態を安全に変更する方法
- [動作原理（韓国語）](docs/architecture.md) — フックとコマンドの動作
- [保護範囲と制限（韓国語）](docs/threat-model.md) — 保護される操作と対象外の操作
- [調査根拠（韓国語）](docs/research.md) — 根拠と参考資料

## ライセンスとセキュリティ報告

DELETE-DENIEDはMIT Licenseで公開しています。セキュリティ問題は[セキュリティ報告手順（韓国語）](SECURITY.md)に
従って報告してください。
