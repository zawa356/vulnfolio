# vulnfolio

**モジュラー型脆弱性インテリジェンス・資産管理基盤（開発中）**

CVE/KEV/EPSS等の公式データと、SNS・セキュリティコミュニティ等の非公式シグナルを整理し、次に問題化しそうな脆弱性・現在進行中の脅威・自分が対応すべき事項を、一つのWebダッシュボードにまとめるOSSプロジェクトです。

> **実装状況（2026-11-19）：M0 / M1a / M1b PoC完了。** M1cの実機収集・認証付きHTTPS転送は未実装です。SNS、LLM、MCPも未実装です。進捗の最新情報は[GitHub Issues](https://github.com/zawa356/vulnfolio/issues)を参照してください。

## Quick start — M0 / M1 local PoC

Python 3.11+。Vulnerability-Lookupの公開APIから**少数の指定CVEだけ**取得し、SQLite→REST API→Tabler画面で確認できます。

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m vulnfolio.vulnerability_sync --id CVE-2024-3094
uvicorn vulnfolio.vulnerability_api:app --host 127.0.0.1 --port 8000
```

- グローバルCVE: http://127.0.0.1:8000/
- **My Environment:** http://127.0.0.1:8000/environment
- REST API docs: http://127.0.0.1:8000/docs

My Environmentでは、案件Profile→Asset→Installed Softwareを手動登録、または**共通JSONを手動インポート**し、ローカルに保存したCVEの構造化`affected`情報に基づく**影響候補**を表示できます。案件別の対応状況も記録します。候補は影響確定ではなく、OSベンダーのバックポート/KB判定はまだできません。

**認証機能はありません。ループバックのみで起動し、顧客の機密資産データを投入しないでください。** [M1手動管理](docs/poc-m1.md) / [収集JSONインポート](docs/poc-m1-import.md)。

取得元が利用できない場合でも、既存のローカル保存データは表示できます。PoCには認証を実装していないため**インターネット公開しない**でください。UIはTablerのバージョン固定CDNを使用しています。

[詳しい操作・構成・実API調査・既知の制限](docs/poc-m0.md)。

## 目標

- 製品・ベンダーを事前に限定せず、脆弱性情報を横断収集・検索する。
- 公式の危険度や悪用状況と、SNS等の注目度・未確認の兆候を**区別して**可視化する。
- ルールベースの数値評価、LLMによる説明と予測（24時間 / 7日 / 30日）を組み合わせる。
- 案件ごとのプロファイル・資産台帳・影響判定・対応状況を管理する。
- Linux/Windowsのエージェントレス収集から始め、JSONインポートとHTTPS送信の両方を扱う。
- Web UI・REST API・MCPを提供する。主用途は個人利用で、知人との小規模共有を想定する。
- **追加の従量課金は原則0円**。無料OSS・既存設備・利用中のAIサブスクリプションを優先する。

## 主要ドキュメント

| 文書 | 内容 |
| --- | --- |
| **[文書一覧と運用ルール](docs/README.md)** | **仕様・契約・PoCの入口。Issuesを進捗の正本として扱う** |
| [要件定義（決定事項・将来要件）](docs/requirements.md) | 機能・非機能・データの扱い |
| [アーキテクチャ案](docs/architecture.md) | 独自中間レイヤー、DB、API、収集・AI分析 |
| [モジュール化設計](docs/modularity.md) | プラグイン境界・共通API・機能差異の吸収方針 |
| [M0 PoC](docs/poc-m0.md) | 最小CVEデータ取得・SQLite・REST・Web UIの実装と制限 |
| [M1a PoC](docs/poc-m1.md) | ローカル案件・資産登録、影響候補、対応履歴、権限上の制限 |
| [M1b JSONインポート](docs/poc-m1-import.md) | 収集JSONをProfileへ手動アップロード・冪等取込する手順 |
| [Phase 0 PoC](docs/poc-phase0.md) | 3種類の収集レポートの共通変換・検証結果・制約 |
| [OSS比較](docs/oss-comparison.md) | Vulnerability-Lookup vs OpenCTI、選定根拠 |
| [収集方式・データ契約](docs/data-ingestion.md) | SNS、エージェントレス資産収集、収集方式 |
| [CollectionEnvelope v0.1.0](docs/contracts/collection-envelope-v0.1.md) | **実装済みJSON入力契約・現在の制限** |
| [UI設計原則](docs/ui-guidelines.md) | 標準キット優先、情報設計、配色 |
| [初期ロードマップ（履歴資料）](docs/roadmap.md) | 当初の計画案。**現在の作業状態はGitHub Issuesが正本** |

## 現時点の技術方針

収集・照合・AI・公開系は**交換可能なモジュール境界**を設けます（初期はモジュラーモノリス、不要なマイクロサービス化はしません）。

Vulnerability-Lookupを**第一候補の既存バックエンド**とし、vulnfolio固有のSNS観測・LLM分析・予測・資産管理・対応履歴を**独自中間APIと拡張DB**に保持する方式を優先検証します。外部公開APIから始め、必要に応じてセルフホストに切り替えられる構造を目標とします。

OpenCTIは攻撃者、マルウェア、キャンペーン等の関係分析に強く、現段階では比較対象・将来の連携候補です。各モジュールは小さく実装・検証し、選択したOSSと接続します。

## セキュリティ上の境界

公開脆弱性情報と、案件固有の資産・構成・対処履歴は分離します。後者は公開Web/API/MCPから既定で参照させません。SNS上の未確認情報は確認済みの脅威と区別し、出典・観測時刻・評価根拠を保持します。

## Phase 0 オフラインPoC（M0に取り込み済み）

Ansible / Vuls / OpenVASの**保存済み・サンプルレポート**を、同じJSON契約に変換するアダプターとテストはmainに取り込み済みです。**実ホストへのSSH/WinRM収集と認証付きHTTPS自動送信は未実装**です。共通JSONのローカル**手動インポートはM1bで実装済み**です。

```bash
PYTHONPATH=src python -m vulnfolio.cli --driver ansible --profile demo-profile --input tests/fixtures/ansible.json
PYTHONPATH=src python -m unittest discover -s tests -v
```

## 開発方針

小規模OSSとして無理のない範囲から始め、M0の**CVE取得＋検索＋ダッシュボード**とM1a/M1bの**資産照合＋JSON手動取込**は実装済みです。続けて実機収集、認証付き転送、SNS分析、LLM予測、通知・レポートを縦スライスで拡張します。UIはBootstrap系の既存管理画面キットを優先し、独自UI部品を増やしません。

---

このREADMEは現在の操作とナビゲーションを示します。仕様の確定・未決は[文書一覧](docs/README.md)から確認してください。

## 開発管理（GitHubを正本とする）

- **[Development Board](https://github.com/users/zawa356/projects/3)** — GitHub ProjectsのTodo / In Progress / Doneで作業状態を追跡
- **[Roadmap Issue #2](https://github.com/zawa356/vulnfolio/issues/2)** — Epic・Milestone・Backlogの入口
- **[Milestones](https://github.com/zawa356/vulnfolio/milestones)** — 動く機能の到達目標（期日は固定しない）
- **[Issues](https://github.com/zawa356/vulnfolio/issues)** — 作業単位・受入条件・技術調査・検討事項
- **[Pull Requests](https://github.com/zawa356/vulnfolio/pulls)** — 実装・レビュー・CI・変更履歴

**[M0 — CVE→DB→Web](https://github.com/zawa356/vulnfolio/milestone/1)は完了**、次は **[M1 — Asset Relevance](https://github.com/zawa356/vulnfolio/milestone/2)** を進めます。各イテレーションで動作する縦スライスを完成させた後、次の優先順位を見直します。Issueを作成し、ブランチ・PRを紐付け、CIと受入条件を満たしてからマージする運用です。

**進捗・優先順位・完了判定はGitHub Issues/Projects/Milestonesを正本**とします。`docs/roadmap.md`は当初の実装方針・長期候補の参考資料であり、進行状況の二重管理はしません。
