# CollectionEnvelope v0.1.0 — 現行入力契約

- スキーマバージョン: **`0.1.0`**
- 出力元の正本: [`contracts.py`](../../src/vulnfolio/contracts.py)、[Ansible Adapter](../../src/vulnfolio/adapters/ansible.py)
- 現行Importerの正本: [`inventory_import.py`](../../src/vulnfolio/inventory_import.py)
- 用途: **エージェントレス収集のオフライン結果**をツールに依存しない形式に正規化。上位レイヤーはAnsible/Vuls/OpenVAS固有形式を直接解釈しない。
- 注意: JSONの形式と項目は実際のコードから導出。将来変更時はバージョン管理する。完全なJSON Schemaファイル・外部互換保証はまだない。

## 現行JSONの例（架空の識別子）

```json
{
  "schema_version": "0.1.0",
  "profile_id": "profile-id-from-web",
  "collector": {
    "driver": "ansible",
    "capabilities": ["asset_inventory", "installed_packages", "windows_kb"]
  },
  "observed_at": "2026-11-19T04:00:00Z",
  "status": "partial_success",
  "observations": [
    {
      "asset_id": "linux-test",
      "os": {
        "family": "RedHat",
        "distribution": "RedHat",
        "version": "9.4",
        "build": null
      },
      "packages": [
        {
          "name": "openssl",
          "version": "3.0.7",
          "release": "27.el9_4",
          "epoch": "1",
          "arch": "x86_64",
          "manager": "rpm"
        }
      ],
      "patches": [],
      "inventory_scope": "reported",
      "source": "ansible"
    }
  ],
  "findings": [],
  "errors": [
    {"asset_id": "offline-test", "reason": "unreachable"}
  ]
}
```

## トップレベル

| フィールド | 意味と現在の受理条件 |
| --- | --- |
| `schema_version` | `0.1.0`で固定、他版は拒否 |
| `profile_id` | インポート先のProfile IDと完全一致が必要 |
| `collector.driver` | 文字列、空欄不可（最大80文字）。例：`ansible`、`vuls`、`openvas` |
| `collector.capabilities` | Adapterが申告する能力配列。現行Importerは形式検証・能力の認証は行わない |
| `observed_at` | 取得日時文字列または`null`。現行Importerは厳密な日時形式まで検証しない |
| `status` | `success` / `partial_success` / `failed` / `empty` |
| `observations[]` | 資産観測レコード。最大200資産 |
| `findings[]` | スキャナーの脆弱性判定。**現行Importerは非空なら全体拒否（HTTP 422）** |
| `errors[]` | 収集元ごとの失敗。最大200件。Importerは件数のみ保存 |

### 観測レコード

- `asset_id`: 必須・空不可のホストキー（最大180文字）。同一バッチ内で大文字小文字を無視して重複不可。現実装ではホスト名に基づくため**ホスト名変更は別資産になりうる**。
- `os`: `family` / `distribution` / `version` / `build` （文字列または`null`）。Importerは`family`、`distribution`、`version`をAsset列へ格納。**buildは検証のみで保存していない**。
- `packages[]`: `name`（必須） / `version` / `epoch` / `release` / `arch` / `manager`。それぞれ文字列または`null`、一資産2000件/バッチ5000件の上限。
- `patches[]`: Windows KBなどの文字列ID。最大2000件/資産。**修正済み判定や累積パッチ推論には利用しない**。
- `inventory_scope`、`source`: プロデューサーの観測範囲・出典。Importerが解析に利用するのは当面上記必須項目。
- `findings[]`: `VulnerabilityFinding`は別概念であり、`observations`への自動格上げをしない。

## 取り込み動作・上限

- `POST /api/v1/profiles/{id}/imports` は**ループバック限定**、`Content-Type: application/json`、最大2 MiB。
- JSON内容・文字列長・重複を検証後、SQLトランザクションで原子的に保存。
- **同一Profileと同一正規化JSON内容**（キー順に依らないJSONのSHA-256）で二重取り込みを抑止。タイムスタンプが違えば別バッチ。
- 手動登録製品とインポート製品は別テーブルで管理する。
- 各観測の非空`packages`は同ホストの前回インポート製品を置換。**空配列・対象外ホストでは削除しない**ため、古い製品情報が残り得る。
- 非空の`patches`のみ最後のKBスナップショットを更新。空配列は前回のKB情報を保持（情報の鮮度と確定的な欠如を区別する仕様は未完）。
- `errors`は件数だけ保持。認証エラー本文や秘密文字列は永続化しない。
- CVEとの照合は既存の**構造化`affected`製品名**を用い、バージョンの完全一致が記載されていても**修正状態の確定はしない**。

## Source Adapterの実際の差

| Source | 生成するもの | M1bへの適用 |
| --- | --- | --- |
| Ansible | OS/パッケージ/KB観測、`findings=[]` | 現行対応 |
| Vuls | OS/パッケージ観測、`scannedCves`があればFinding | **Findingを伴う入力は丸ごと拒否**。観測のみの出力なら取り込み可能 |
| OpenVAS/Greenbone | NVT Findingと観測ホスト、パッケージ一覧は空が多い | 非空Findingを伴う入力は丸ごと拒否 |

**この仕様は、完全なJSONの独立検証器・セキュアな業務アップロードAPIを提供するものではありません。** 認証・権限制御・厳密なスキーマ・安定資産ID・スキャナーFinding取込は後続Issueで設計する。

## 関連資料

- [M1b手順](../poc-m1-import.md)
- [収集方式](../data-ingestion.md)
- [GitHub Issue #24](https://github.com/zawa356/vulnfolio/issues/24)
