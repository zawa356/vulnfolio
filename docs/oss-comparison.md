# 既存OSS比較: Vulnerability-Lookup vs OpenCTI

- 調査日: 2026-11-19
- 評価対象: **vulnfolio**（脆弱性の統合・SNS注目度/LLM予測・個人/案件別対応）
- 暫定結論: **Vulnerability-Lookupを第一候補**。OpenCTIは将来のCTI連携/代替候補。
- この文書の比較は公開資料上の機能適合性。個別API仕様・性能・利用規約は実測・調査前。

## 1. それぞれの主目的

### Vulnerability-Lookup

- CIRCL主導の脆弱性情報集約・検索・相関・CVD（協調的脆弱性開示）支援
- CVE等の識別子を跨ぐ情報参照、複数のFeeder、watchlists、Sightings、REST API
- GitHub関連プロジェクトに **VulnMCP** と **ML-Gateway** が存在
- v7.0.0（2026-11-16）ではEUVD取り込み等の拡張も進行

### OpenCTI

- 脆弱性だけでなく、Threat Actor、Malware、Intrusion Set、Campaign、Indicator、Observable、Report、Case等を**関係グラフ**として扱うCTIプラットフォーム
- **STIX 2.1**を中心とするデータモデル、Connectorによる取り込み/エンリッチ、GraphQL API、カスタムダッシュボード、ケース管理
- 脆弱性の詳細やSoftwareオブジェクト、脅威/攻撃者との関係表現、ルールによる関連付けに強い

## 2. 機能適合性マトリクス

| 項目 | Vulnerability-Lookup | OpenCTI | vulnfolio観点 |
| --- | --- | --- | --- |
| CVE中心の検索・統合 | ◎ 基本用途 | ○ 対応するがCTIモデル中心 | 最優先 |
| NVD/CVE系Feeder | ◎ 専門的 | ○ Connector構成次第 | 最優先 |
| KEV/EPSS連携 | ◎ 対応機能あり | ○ 取り込み構成を要確認 | 最優先 |
| 脆弱性別のSNS/PoC言及 | ◎ Sightings専用機能 | ○ 外部情報・関係をモデル化 | 目玉 |
| CVE未採番の噂 | △ 独自事象で補完したい | ○ グラフに置きやすいが実装要 | 目玉 |
| Watchlist/通知 | ◎ 既存機能 | ○ ケース/通知/監視が可能 | 将来 |
| 攻撃者/マルウェア/攻撃キャンペーンの相関 | △ 中核ではない | ◎ 中核機能 | 今は対象外 |
| IOC/Indicator/Observable/STIX | △ 中核ではない | ◎ 強い | 将来 |
| ケース管理・チームCTI調査 | △ 限定的 | ◎ 強い | 小規模のみ |
| 資産との脆弱性照合 | △ 独自実装中心 | ○ ソフトウェア・資産関連/ルールを利用可能 | 自前の案件データが必要 |
| REST API | ◎ あり | △ 主軸はGraphQL | 中間APIで吸収 |
| GraphQL API | △ 主軸ではない | ◎ あり | 選定理由の一要素 |
| MCP | ◎ 関連OSS VulnMCPあり | △ 連携実装の設計・検証が必要 | 重要 |
| 機械学習 | ○ 別コンポーネントML-Gateway | ○ エンリッチ/自動化の仕組みあり | 独自LLM予測はどちらも要開発 |
| 独自UIの上流非依存化 | ◎ REST経由で構成しやすい | ○ GraphQL経由でも可 | どちらも実現可能 |
| 個人規模の維持 | ○ 相対的に組みやすい | △ 構成が大きい | 重要 |

評価は**用途適合**であり、汎用機能数の優劣ではない。OpenCTIにもVulnerability Management関連機能やソフトウェア利用に基づく伝播ルールがあるため、「資産管理ができない」とは評価しない。

### Sightingsという語の違い

- Vulnerability-LookupのSightingsは「この脆弱性がSNS・PoC・リソース等で言及/観測された」という意味で使いやすい。
- OpenCTIのSTIX SightingはSTIX上のオブジェクトがどの組織・システム等で観測されたかを表す**関係**。SNSの「言及数ランキング」をそのまま表すものではない。
- 双方とも、vulnfolio独自の「注目度時系列」「独立発信者」「確からしさ」「予測」をそのまま提供する保証はない。

## 3. 運用構成と費用面

### Vulnerability-Lookup

- 脆弱性コーパスの永続ストレージ: Kvrocks
- ユーザー/コメント/Sightings/Watchlists等: PostgreSQL
- キャッシュ: Valkey/Redis系
- 既存公開APIの利用から始められ、必要になったらセルフホストへ移行する構想を取りやすい
- 公開APIの規約/制限や大容量データの扱いは事前検証が必要

### OpenCTI

- 主な依存: Elasticsearch/OpenSearch、Redis、RabbitMQ、S3互換ストレージ等
- データ収集はConnector/Workerを含む構成。個人がすべての役割・コネクタを維持すると負担になりやすい
- 脅威グラフ・各種ダッシュボード・ケース管理はその負担に見合う機能がある

※ **正確な必要RAM/CPU/ディスクは、接続するソース数、収集件数、保持量、同時利用数による**。公式の公開運用向け推奨値を個人PoCの最小要件と取り違えない。両OSSとも「完全無料運用」を保証するわけではない。

## 4. API・MCP・LLM連携

| 連携観点 | Vulnerability-Lookup | OpenCTI |
| --- | --- | --- |
| 既存データ取得 | REST APIとPythonクライアント | GraphQL API・Python SDK |
| データ追加 | Feeder、Sightings API、編集/投稿機構等 | Connector/GraphQL/STIX |
| MCP | VulnMCPのツール群を検証できる | 独自/サードパーティMCPの互換性・範囲を検証 |
| LLMによる7日予測 | 独自サービスで実装 | 独自サービスで実装 |
| SNSの意味解析 | 別分析キューが必要 | 別分析キューが必要 |
| サブスク型LLMの定期実行 | 既存MCPだけでは成立保証なし | 同左 |

**推奨:** 独自の中間API/DBへSNSの原観測・分析・将来予測・案件評価を蓄積し、上流には独自情報を無理に書き戻さない。上流のAPIで自然に表現可能なSightings等は別途利用価値を検証する。

## 5. ライセンス

- Vulnerability-Lookup: **AGPL-3.0系**（現行上流の正式なLICENSEを確認）
- OpenCTI Community Edition: **Apache-2.0**。同じGitHubリポジトリ内にEnterprise Editionライセンスの範囲も存在するため、対象機能のCE/EE区別が必要。
- vulnfolioは独立OSSとして構築予定。**API連携かコード流用/改変かで法的論点が変わる**ため、依存関係・配布方法を固めた段階でライセンスレビューする。
- データ自体の再配布条件はソフトウェアライセンスと別に確認する（特にSNS、ベンダーアドバイザリ）。

## 6. 今回の採用判断

**第一候補: Vulnerability-Lookup + 独自中間レイヤー + 独自拡張DB**

理由:

1. 統合したいデータの中心が**脆弱性（CVE/JVN/KEV/EPSS）**である。
2. **Sightings**と既存MCPが、SNS観測・AI連携という独自性と近い。
3. OpenCTIの強みである**攻撃グループ/マルウェア/IOC/インシデントの総合CTI分析**は、初期要件に対して過剰になりやすい。
4. 個人運用・追加API課金原則0円・中間レイヤーの最小構成という条件に適合しやすい。
5. 上流を無改造で使い、外部API→セルフホスト切替に備えられる。

**変更条件:** 重大なAPI制限で必要なデータが取得できない、セルフホスト資源が許容できない、データの権利・公開条件が要件と矛盾する、あるいはCTIグラフが主目的へ変わったときは再評価する。

## 7. PoCで回答する質問（実装前）

- [ ] 公開APIから必要なCVE・KEV・EPSS・Sightingsデータを正確に取得できるか（量/鮮度/ページング/差分取得）
- [ ] 利用規約・レート制限・認証条件に抵触せず、独自Web/APIで表示できるか
- [ ] CVE未採番の事象を独自DBへ安全に追加し、後で既存CVEと関連付けられるか
- [ ] VulnMCPの既存ツールだけで検索/詳細照会/関連情報取得をどこまでできるか
- [ ] 自前MCPの分析結果書き戻しとサブスクLLMの日次定期実行は、規約上・機能上成立するか
- [ ] 外部APIとセルフホストの切替時に独自ID・案件・対応履歴が維持できるか
- [ ] 上流障害・取得制限時にキャッシュからの表示やフォールバックが可能か
- [ ] 実測のCPU/RAM/容量/更新時間で、小規模なセルフホストが現実的か

## 8. 公式資料

- Vulnerability-Lookup [GitHub](https://github.com/vulnerability-lookup/vulnerability-lookup) / [ドキュメント](https://www.vulnerability-lookup.org/documentation/) / [アーキテクチャ](https://www.vulnerability-lookup.org/documentation/architecture.html) / [Sightings](https://www.vulnerability-lookup.org/user-manual/sightings/)
- [VulnMCP](https://github.com/vulnerability-lookup/VulnMCP) / [ML-Gateway](https://github.com/vulnerability-lookup/ML-Gateway) / [v7.0.0リリースノート](https://www.vulnerability-lookup.org/2026/11/16/vulnerability-lookup-7-0-0/)
- OpenCTI [公式ドキュメント](https://docs.opencti.io/latest/usage/getting-started/) / [データモデル](https://docs.opencti.io/latest/usage/data-model/) / [GraphQL API](https://docs.opencti.io/latest/reference/api/) / [デプロイ構成](https://docs.opencti.io/latest/deployment/overview/) / [ケース管理](https://docs.opencti.io/latest/usage/case-management/) / [ルールエンジン](https://docs.opencti.io/latest/administration/reasoning/)
- OpenCTI [GitHubとライセンス](https://github.com/OpenCTI-Platform/opencti) / [Connector一覧](https://github.com/OpenCTI-Platform/connectors)

関連: [要件](requirements.md) / [アーキテクチャ](architecture.md) / [ロードマップ](roadmap.md)
