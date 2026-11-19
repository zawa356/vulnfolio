# vulnfolio ドキュメントの入口

ここは**仕様・設計・検証結果**の置き場です。**優先順位、進捗、担当、受入条件の最新状態はGitHub Issues / Milestones / Projectsを正本**とし、Markdownチェックリストでは二重管理しません。

- [GitHub Project（Todo / In Progress / Done）](https://github.com/users/zawa356/projects/3)
- [全体Roadmap Issue #2](https://github.com/zawa356/vulnfolio/issues/2)
- [Milestones](https://github.com/zawa356/vulnfolio/milestones)
- [Issue #24: M1c エージェントレス収集・HTTPS送信](https://github.com/zawa356/vulnfolio/issues/24)

## 1. 参照先の選び方

| 何を確認したいか | 正本・参照先 | 更新トリガー |
| --- | --- | --- |
| いま何を作っているか・何が完了したか | [GitHub Issues / Milestones](https://github.com/zawa356/vulnfolio/issues) | Issue・PRの更新時 |
| 採用方針・要求・スコープ | [要件定義](requirements.md) | 要件が増減・変更したとき |
| 全体構成・モジュール境界 | [アーキテクチャ](architecture.md)、[モジュール化](modularity.md) | 境界・API方針変更時 |
| SNS/資産収集パイプライン | [収集方式](data-ingestion.md) | Adapterや収集経路変更時 |
| **現在受理するJSONの厳密な仕様** | [CollectionEnvelope v0.1.0](contracts/collection-envelope-v0.1.md) | AdapterまたはImporter変更時 |
| 起動、ユーザー操作、既知の制限 | [M0](poc-m0.md)、[M1a](poc-m1.md)、[M1b](poc-m1-import.md)、[M1c収集PoC](poc-m1c-agentless.md)、[M1c認証付きHTTPS](poc-m1c-https.md) | 関連PRのマージ時 |
| 先行技術と設計判断 | [OSS比較](oss-comparison.md)、[UI規約](ui-guidelines.md) | 技術判断を変えるとき |
| 当初の実装順・調査メモ | [旧ロードマップ案](roadmap.md)、[Phase 0 PoC](poc-phase0.md) | **履歴資料**、現行の進捗判定に使わない |

## 2. 実装済みと構想の境界（2026-11-19 時点）

**M0（完了）:** CIRCL公開APIから少数CVEをID指定取得 → CVE Record v5の正規化 → SQLite → FastAPI一覧/詳細/ヘルス → Tabler。実APIの1件Smokeは[GitHub Actions](https://github.com/zawa356/vulnfolio/actions/runs/44445355711)で成功。

**M1a（完了）:** ローカル案件Profile、Asset、手動Installed Software → CVE `affected`に基づく**影響候補** → 資産別の手動判定履歴。実ブラウザテストあり。

**M1b（完了）:** 収集済みのAnsible/Vuls/OpenVAS風レポートを共通JSONへ**オフライン変換**、共通JSONの`observations`をローカルWeb/RESTから案件資産へ**手動インポート**。同一JSON再投入、空観測、手動製品の保護をテスト済み。**Vuls/OpenVASの非空`findings`は取り込み拒否**。

**M1c（コード実装・実機未検証）:** Linux/WindowsのAnsible/PowerShell読み取り収集→既存共通JSONのローカル出力（[詳細](poc-m1c-agentless.md)）。

**M1c HTTPS送信PoC:** Profile単位トークン認証、証明書検証、再送、既存Importerへの接続（[実装・試験と制約](poc-m1c-https.md)）。**ローカル実TLSのみ検証、LAN/本番未対応。**

**今後:** Linux/Windowsの権限ある実機での受入とLAN転送の検証、CVEとの厳密な影響判断（OSベンダーバックポート/Windows KB）、SNS観測、LLM予測、通知、MCP、認証付き公開。

> **重要:** UI/資産管理APIは認証なしのローカルPoCです。HTTPSアップロードのみ別経路でトークン認証を実装しています。**全体として本番向け認証・公開設計は未完了**です。ループバック制限は認証の代替になりません。実顧客情報を投入せず、LAN/インターネットへ無審査で公開しないでください。

## 3. 文書運用ルール

1. Issueで「何を変更するか・受入条件」を管理し、PRで変更・テスト証跡を残す。
2. PRでAPI、データ契約、画面、起動コマンド、セキュリティ条件を変えたら、**同じPRで関係するdocsを更新**する。
3. 既存仕様に触れる新しい契約ができた場合、現行の契約文書に追記し、旧案は**履歴**と明記する。
4. PoCの「実測」と「合成fixtureのテスト」を混同しない。検証済み環境・前提・未検証範囲を残す。
5. 実装されていない機能を「対応済み」と書かない。取得できない/未判定は成功として扱わない。
6. docsの相対リンクはCIで存在確認する。**GitHub Issueへのリンクはツールの現物確認**を優先する。
