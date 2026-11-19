# M1c 後半 — 認証付きHTTPSインベントリアップロード（PoC）

- 対応: [Issue #31](https://github.com/zawa356/vulnfolio/issues/31) / 親 [#24](https://github.com/zawa356/vulnfolio/issues/24)
- 状態: **ローカルの本物のTLS（Uvicorn）で検証するPoC**。LAN/Internetへの本番公開を許可するものではありません。
- 成果: Agentless収集の共通JSONを、**実HTTPS + ProfileスコープのBearer Token**で既存M1b Importerに渡す。通信失敗時は元JSONを残し、同一JSONは重複保存しない。
- 非対象: 実ホストへのSSH/WinRM接続試験（#30）、SaaS向けユーザー認証、複数利用者管理、本番用公開Ingress/Reverse Proxy、監視/WAF/分散レート制限。

## 境界とデータフロー

```mermaid
flowchart LR
  A["Linux / Windows\n（別の収集モジュール）"] --> B["CollectionEnvelope v0.1.0\nローカルJSONファイル"]
  B --> C["ingest_upload.py\nTLS検証・Bearer Token・再試行"]
  C -->|Direct HTTPS| D["POST /api/v1/ingest/profiles/{id}/imports\nTLS必須 / Profileスコープ確認"]
  D --> E["共通Importer（M1b）\n検証・冪等・トランザクション"]
  E --> F[("SQLite: Profile / Asset / Product")]
  B --> G["閉域網：手動でJSON持込\n（M1bを維持）"]
  G --> E
```

既存の`POST /api/v1/profiles/{id}/imports`、Profile/Asset/Assessmentの取得・変更APIおよび`/environment`は**ループバック限定のまま**です。新しいBearer Tokenは**指定ProfileのJSONインポート権限だけ**を付与し、資産閲覧や対応状況の変更を許可しません。

## 1. 認証設計

- **トークン**: `vf_`＋暗号学的乱数32バイト（約256ビット）のURL-safe文字列。人間が決める短いパスワードは受理しない設計。
- **認証ファイル**: `VULNFOLIO_INGEST_TOKENS_FILE`でパスを指定。JSONには`id`、`profile_id`、`sha256`のみを格納し、Bearerの平文はサーバー側に保存しない。
- **ファイル権限**: POSIX環境では認証ファイルとBearerファイルに0600相当を要求。WindowsではファイルACLを管理者が設定する（現行PoCはWindows ACLを検査しない）。
- **スコープ**: トークンは発行時に指定した**一つのProfile IDだけ**で有効。他Profileへのアップロードは401。
- **ローテーション**: 新しいトークンを発行→クライアントへ安全に配布→旧トークンIDを失効。資格情報ストアはリクエストごとに再読込するため再起動不要。
- **失効管理**: IDで個別失効可能。アクセストークンの有効期限・発行者による監査ログ・rate limitは現段階では未実装。
- `Authorization`をURLのクエリ文字列に含めず、ログやGitに書かない。

## 2. ローカルHTTPS検証の起動例

先に既存M1aの**ループバック専用HTTP**でProfileを作成し、そのIDを取得してから、HTTPプロセスを停止してHTTPSサービスを起動します。同じ`VULNFOLIO_DB`を使うこと。

### 2.1 テスト用の証明書

実際の運用は自組織/信頼できるCAが発行したサーバー証明書を使います。以下のコマンドは**127.0.0.1でのPoC専用**です。

```bash
mkdir -p private-data/tls private-data/auth
chmod 700 private-data/tls private-data/auth

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout private-data/tls/localhost.key \
  -out private-data/tls/localhost.crt \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
chmod 600 private-data/tls/localhost.key
```

### 2.2 Profile固有Tokenを発行

```bash
python -m vulnfolio.ingest_credentials issue \
  --store private-data/auth/tokens.json \
  --profile <profile-id> \
  --token-output private-data/auth/collector.token

# ID・スコープの一覧（秘密値は表示しない）
python -m vulnfolio.ingest_credentials list --store private-data/auth/tokens.json
```

- `<profile-id>`をブラウザで作成した32文字IDへ置き換えます。発行CLIはProfileのDB存在を検証せず、**アップロード時にDBとの整合性を検証**します。
- `collector.token`は**平文Bearerが一度だけ書き込まれるファイル**です。安全な手段で踏み台に配布し、0600・適切な所有者/Windows ACLを設定。Gitに追加しないでください。
- サーバー上に残した不要な平文ファイルは、クライアント側の安全な保管を確認した後に削除してください（サーバーのJSON Storeにはハッシュのみが必要）。
- 失効: `python -m vulnfolio.ingest_credentials revoke --store private-data/auth/tokens.json --id <token-id>`。
- トークンをコマンド引数・環境変数・GitHub Actionsの平文ログに直接入れないこと。

### 2.3 UvicornをDirect TLSで起動

```bash
export VULNFOLIO_INGEST_TOKENS_FILE="$PWD/private-data/auth/tokens.json"
# 既存DBの場所は従来どおり VULNFOLIO_DB（省略時はdata/vulnfolio.db）

uvicorn vulnfolio.vulnerability_api:app \
  --host 127.0.0.1 --port 8443 \
  --ssl-certfile private-data/tls/localhost.crt \
  --ssl-keyfile private-data/tls/localhost.key \
  --no-proxy-headers
```

**必ず`--no-proxy-headers`を付けます。** このPoCではASGI接続の`scheme=https`でTLSを検査するため、外部由来の`X-Forwarded-Proto`を信用しないDirect TLSが前提です。

`--host 0.0.0.0`などでLANに公開すると、同一アプリのグローバル脆弱性閲覧API・OpenAPIも接続可能になり、認証なしのローカルUI/APIは接続元による制限のままです。**本番公開には認証・Ingress境界・セキュリティレビューを追加する必要があります。** リバースプロキシでループバック認証を迂回する構成は使用しないでください。

### 2.4 クライアントからアップロード

Linux/Windowsの収集が終わった後、**別プロセス**で実行します。JSONファイルは送信に成功しても削除されません。

```bash
python -m vulnfolio.ingest_upload \
  --base-url https://127.0.0.1:8443 \
  --profile <profile-id> \
  --input private-data/collected.json \
  --token-file private-data/auth/collector.token \
  --ca-file private-data/tls/localhost.crt \
  --attempts 3
```

- 内部CAの場合は`--ca-file`に認証済みのCA証明書を指定。公開CAなら省略可能。**TLS検証を無効化するオプションはありません**。
- クライアントがHTTPS以外のURL、ユーザー名/パスワード埋込URL、リダイレクト先にBearerを送信することはありません。
- 元JSONの`profile_id`とコマンド引数の一致を送信前に確認します。
- 一時的な通信障害、429・一部の5xxのみ最大3回（指定上限5回）再試行します。401/403/413/422と3xxは再試行しません。
- 標準出力はImport ID/件数・重複状態の概要のみ。ソフトウェア/KBなどの収集本文やTokenは出しません。
- ネットワーク障害・重複アップロード時も**元ファイルを保持**します。スケジュール実行や自動再送キュー（永続ジョブ管理）は未実装です。

## 3. APIの対応範囲

| 項目 | 挙動 |
| --- | --- |
| Endpoint | `POST /api/v1/ingest/profiles/{profile_id}/imports` |
| HTTPS | 必須（Direct TLS） |
| Auth | `Authorization: Bearer ...`（Profile単位） |
| Media type | `application/json` |
| Max body | 2 MiB |
| Input schema | [CollectionEnvelope 0.1.0](contracts/collection-envelope-v0.1.md) |
| Import | M1bの`InventoryImporter`を再利用。重複Content SHA-256を抑止 |
| 401 / 403 | Token不正・別Profile / HTTP・Origin付きブラウザ等 |
| 413 / 415 / 422 | サイズ超過・Content-Type不正・JSON/Schema不正 |
| 503 | Credential Store未設定・破損・権限不備（fail closed） |
| 無認証の資産読み取り | 引き続き不可（loopback限定） |

## 4. 自動テストで確認すること

```bash
python -m unittest discover -s tests -p 'test_ingest_*.py' -v
```

- TestClient: トークン発行・失効・ローテーション、別Profileへの拒否、HTTP拒否、Origin拒否、破損・不適切なファイル権限でfail-closed、取り込みサイズ/形式、重複抑止
- MockTransport: 429/503等の再試行とリダイレクト禁止
- **実TLSプロセス**: テスト用OpenSSL証明書とUvicornを`127.0.0.1`で起動し、実CLIから証明書を検証してアップロード。信頼されない自己署名証明書では失敗することも確認
- すべて**合成データとloopback通信**のみ。実際のLinux/Windowsホストは利用しない

## 5. 未対応・本番前の残留リスク

- 単一ユーザー/プロセスのPoCであり、**本格RBAC、分散Rate Limit、監査イベント、秘密情報保管サービス、保持・削除ポリシー**は未整備。
- APIトークンの有効期限、mTLS、Token-IDベースの発行監査、Windows ACL検査も未実装。
- リバースプロキシ経由のHTTPS終端・Forwarded Headerの信頼関係は未サポート（Direct TLSのみ）。
- 受信したインベントリ内容は既存M1のSQLiteに保存。保存時暗号化や顧客組織ごとのテナント分離はない。
- **保存側のスキーマではWindows OS Buildを永続化していない**。KB/ビルド照合による脆弱性確定はできない。
- リアルホストでの収集とLAN越し送信の受入は、権限を得たテスト環境で別途行う。
- 既存のローカル管理APIはネットワーク公開できる認証モデルではないため、バックエンド全体をそのままインターネット公開してはならない。

関連：[M1c収集](poc-m1c-agentless.md) / [M1bの手動インポート](poc-m1-import.md) / [実装方針](modularity.md)
