# Phase 0 PoC：共通収集アダプターとデータ契約

- 実施日: 2026-11-19
- 状態: **Phase 0当時のオフラインデータ変換PoC記録**。現在のM0/M1a/M1bではWeb/REST/SQLite・JSON手動インポートが追加済み。**SSH/WinRM実機収集、Vuls/OpenVASの起動、MCP、認証付きHTTPS送信は現在も未実装**。
- 目的: ツール依存の入力形式をアダプターで吸収し、上位が**同一スキーマ**だけを扱えることを確認する。

## 1. 作成物

| パス | 内容 |
| --- | --- |
| `src/vulnfolio/contracts.py` | 版付き共通エンベロープ・入力検証・Findingの意味 |
| `src/vulnfolio/adapters/ansible.py` | ホスト別Ansible facts/package_facts形式の正規化 |
| `src/vulnfolio/adapters/vuls.py` | Vuls JSON報告の資産観測・脆弱性判定への分離 |
| `src/vulnfolio/adapters/openvas.py` | 保存済みGMP XMLレポートの結果変換 |
| `src/vulnfolio/adapters/__init__.py` | ドライバーレジストリー |
| `src/vulnfolio/cli.py` | ファイル入力→共通JSONのオフラインCLI |
| `tests/fixtures/` | **すべて架空のホスト名・CVE・KBを使った**サンプル |
| `tests/test_adapters.py` | 10種類の互換・入力検証テスト |
| `.github/workflows/ci.yml` | Python 3.11/3.13の自動テスト |

## 2. 実行例

Python 3.11以上。ライブラリの追加インストールは不要（標準ライブラリのみ）。

```bash
PYTHONPATH=src python -m vulnfolio.cli --driver ansible \
  --profile demo-profile --input tests/fixtures/ansible.json

PYTHONPATH=src python -m vulnfolio.cli --driver vuls \
  --profile demo-profile --input tests/fixtures/vuls.json

PYTHONPATH=src python -m vulnfolio.cli --driver openvas \
  --profile demo-profile --input tests/fixtures/openvas.xml \
  --output /tmp/vulnfolio-output.json

PYTHONPATH=src python -m unittest discover -s tests -v
```

Windows/PowerShell例:

```powershell
$env:PYTHONPATH = "src"
python -m vulnfolio.cli --driver ansible --profile demo-profile --input tests/fixtures/ansible.json
python -m unittest discover -s tests -v
```

このCLIは**保存済みファイルの読み込みと変換だけ**を行い、対象ホストへ通信しない。**Phase 0当時は**DBへ保存する機能がなかったが、**現在はM1bのJSON手動インポートAPIで保存できる**（[実装済み入力契約](contracts/collection-envelope-v0.1.md)、[手順](poc-m1-import.md)）。

## 3. 共通出力形式

```json
{
  "schema_version": "0.1.0",
  "profile_id": "demo-profile",
  "collector": {
    "driver": "vuls",
    "capabilities": ["asset_inventory", "installed_packages", "vulnerability_findings"]
  },
  "observed_at": "2026-11-19T01:00:00Z",
  "status": "success",
  "observations": [
    {
      "asset_id": "rhel-demo",
      "os": {"family": "redhat", "distribution": "redhat", "version": "9.4", "build": null},
      "packages": [
        {"name": "openssl", "version": "3.0.7", "release": "27.el9_4", "epoch": null, "arch": "x86_64", "manager": null}
      ],
      "patches": [],
      "inventory_scope": "reported",
      "source": "vuls"
    }
  ],
  "findings": [
    {
      "asset_id": "rhel-demo",
      "vulnerability_id": "CVE-2099-0001",
      "scanner_rule_id": null,
      "severity": null,
      "evidence": "Vuls scannedCves",
      "source": "vuls",
      "assertion": "scanner_reported"
    }
  ],
  "errors": []
}
```

- `AssetObservation`: 取得されたOS・パッケージ・KB等の**観測事実**。
- `VulnerabilityFinding`: ツールが報告した**検査結果**。vulnfolioが独立に存在・悪用を確認した意味ではない。
- Ansibleは原則`findings=[]`。OpenVASはパッケージ一覧を必ず返すとは限らないため、`inventory_scope=host_observed`・空の`packages`を返す。
- CVEがないNVTについても、ルールIDを保持し、偽のCVE番号を割り当てない。
- RPM系の`epoch`/`release`/`arch`を欠落させない。部分失敗のホストは`errors`に記録する。
- 実運用では発見の重複解消・ホストの安定ID・レポート履歴・アクセス権限が別途必要。

## 4. 対応範囲と制約

### Ansible
- 入力は`hosts`または`_meta.hostvars`配下の`ansible_facts`を想定した**定義済み中間JSON**。Ansible Runnerの生イベント全形式にはまだ対応しない。
- Linuxの`package_facts`で返るパッケージ配列を正規化。Windows KB情報は外部PowerShell等で同じ中間JSONへ加える想定。
- **ホストにログインするPlaybookの生成/実行機能は未実装**。

### Vuls
- `serverName`、`family`、`release`、`packages`、`scannedCves`等の既知フィールドを取り込む。
- fixtureは実運用データでなく合成データ。VulsのJSON版差異、出力コマンドや複数ホストレポートを実機結果で評価する必要がある。
- インストール済みパッケージ由来の結果とアプリ依存関係スキャンの区別は今後必要。

### OpenVAS/Greenbone
- 保存済みGMP XMLの`results/result`を処理。NVT OID・CVE・severity・hostを抽出。
- `<results>`内の全項目を解析する完全なGreenboneアダプターではない。XMLサンプルは合成で、XML DTD/ENTITYは拒否する。
- **実機へのネットワークスキャン・認証付きスキャンの自動起動は未実装**。負荷をかけるアクティブスキャンは将来的にも明示的な許可が必要。
- XMLを扱う際のDoS対策、ストリーミング処理、大規模レポート性能は未評価。

### 共通
- モジュール化はデータ変換のPoC段階。非同期Job API（`collect/get_status/get_results/cancel`）の実装は次の契約課題。
- ID照合、永続化、統合API、CPE/OSベンダーの修正情報による照合、異常検知、LLM分析・予測は未実装。
- `status=success`は入力変換成功の意味であり、資産が安全・すべての対象が収集済みという意味ではない。
- 暗号化/鍵管理/認証等は、将来のリモート収集・アップロード機能の段階で実装する。
- 10 MiBはPoC CLIの入力上限であり、プロダクションの適正サイズではない。

## 5. 公開脆弱性API調査の現状

Vulnerability-Lookupの**公開公式資料で確認できる読み取り系API例**:

- `GET /api/vulnerability/{vulnerability_id}`（識別子照会。metadata/sightings等のオプションあり）
- `GET /api/epss/{vulnerability_id}`
- `GET /api/sighting/?vuln_id=...`
- `GET /api/vulnerability/?since=YYYY-MM-DD`（差分同期）
- `GET /api/sighting/stats`（集計）

資料: [API](https://www.vulnerability-lookup.org/documentation/api.html) / [自動利用ガイド](https://www.vulnerability-lookup.org/documentation/access-patterns.html) / [Sightings](https://www.vulnerability-lookup.org/user-manual/sightings/)

**Phase 0当時の注記:** 当時はライブ通信未検証だった。**M0で実CVEの取得・保存・HTTP確認に成功**（[GitHub Actions](https://github.com/zawa356/vulnfolio/actions/runs/44445355711)、[M0記録](poc-m0.md)）。利用条件の未検証部分は[後続Issue #16](https://github.com/zawa356/vulnfolio/issues/16)で追跡。CVE IDの総当たりによる全件同期は避け、案内された差分APIを利用する。

## 6. Phase 0時点で挙げた後続課題（履歴・現在の進捗ではない）

- [x] 上流公開APIから**単一の既知CVE**を取得し、JSONのフィールドを検査する（[M0成功証跡](poc-m0.md)）。
- [ ] VulsとGreenboneの実際の保存済みレポートを使って変換精度を検証する。
- [ ] Ansible/PowerShellの**読み取り専用収集スクリプト**から共通JSONを出力する。
- [ ] AdapterのCapability照会、Job API、失敗/再試行、冪等インポートの仕様を具体化する。
- [ ] 同一資産の複数ソースによる情報の食い違い・重複を保存できるモデルを検証する。
- [x] 中間API+ダッシュボードの極小構成につなぐ（[M0](poc-m0.md)、[M1](poc-m1.md)）。

関連: [全体構成](architecture.md) / [モジュール化設計](modularity.md) / [要件](requirements.md)
