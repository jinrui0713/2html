# YouTube Download Proxy Setup Guide

このプロジェクトは、Cloudflare Workers をフロントエンドおよびプロキシとして使用し、重いダウンロード処理（yt-dlp + ffmpeg）を GitHub Actions にオフロードして、成果物を Cloudflare R2 に保存するアーキテクチャを採用しています。

セットアップを完了するために、以下の手順をユーザー側で実施してください。

## 1. Cloudflare R2 バケットの作成

Cloudflare のダッシュボードで R2 バケットを作成します。

1. Cloudflare Dashboard にログインし、**R2** セクションに移動します。
2. **Create Bucket** をクリックします。
3. バケット名に `proxy-videos` と入力して作成します（`wrangler.toml` の設定と一致させる必要があります）。
4. 作成後、バケットの **Settings** タブで **R2.dev subdomain** を有効にするか、カスタムドメインを接続しておくと便利ですが、Worker 経由で配信する場合は必須ではありません。

## 2. R2 API トークンの取得 (GitHub Actions 用)

GitHub Actions が R2 にファイルをアップロードできるように、アクセスキーを発行します。

1. R2 のトップページ右側にある **Manage R2 API Tokens** をクリックします。
2. **Create API token** をクリックします。
3. 権限: **Object Read & Write** を選択します。
4. 適用範囲: **Specific bucket** > `proxy-videos` を選択（または All buckets）。
5. 作成後、以下の情報をメモしてください（一度しか表示されません）：
   - **Access Key ID**
   - **Secret Access Key**
   - **Endpoint** (例: `https://<account_id>.r2.cloudflarestorage.com`)

## 3. GitHub Secrets の設定

GitHub リポジトリの Settings > Secrets and variables > Actions に以下のシークレットを追加します。

| Secret Name | Value | 説明 |
|---|---|---|
| `R2_ACCESS_KEY_ID` | (取得した Access Key ID) | R2 へのアクセスキー |
| `R2_SECRET_ACCESS_KEY` | (取得した Secret Access Key) | R2 へのシークレットキー |
| `R2_ENDPOINT` | (取得した Endpoint URL) | `https://...r2.cloudflarestorage.com` (バケット名は含めない) |
| `JOB_SECRET` | (任意のランダムな文字列) | Worker と Actions 間の通信認証用パスワード |

## 4. Cloudflare Workers の環境変数設定

Worker が GitHub Actions を起動したり、コールバックを検証したりするために環境変数が必要です。
`wrangler secret put` コマンドを使用するか、Cloudflare Dashboard の Workers > Settings > Variables で設定します。

### 必要な環境変数 / Secrets

| 変数名 | 説明 | 設定方法 (例) |
|---|---|---|
| `GITHUB_TOKEN` | GitHub Personal Access Token (Classic) | `npx wrangler secret put GITHUB_TOKEN` |
| `JOB_SECRET` | GitHub Secrets で設定したものと同じ文字列 | `npx wrangler secret put JOB_SECRET` |
| `GITHUB_OWNER` | GitHub のユーザー名 (例: `your-username`) | `wrangler.toml` の `[vars]` に書くか、Dashboard で設定 |
| `GITHUB_REPO` | リポジトリ名 (例: `2html`) | `wrangler.toml` の `[vars]` に書くか、Dashboard で設定 |

**GITHUB_TOKEN の取得方法:**
1. GitHub の Settings > Developer settings > Personal access tokens > Tokens (classic) へ移動。
2. Generate new token (classic) をクリック。
3. Scopes で `repo` (フルコントロール) または `workflow` を選択して作成。

### 設定コマンド例 (ターミナルで実行)

```bash
# 1. GitHub Token (repo権限付き) を設定
npx wrangler secret put GITHUB_TOKEN
# (プロンプトが出たらトークンを貼り付け)

# 2. Job Secret (GitHub Secretsと同じもの) を設定
npx wrangler secret put JOB_SECRET
# (プロンプトが出たらパスワードを貼り付け)

# 3. その他の変数は wrangler.toml の [vars] セクションに追記するか、以下のように設定
npx wrangler secret put GITHUB_OWNER
# (ユーザー名を入力)

npx wrangler secret put GITHUB_REPO
# (リポジトリ名を入力)
```

## 5. デプロイ

設定が完了したら、Worker をデプロイします。

```bash
npx wrangler deploy
```

## 使い方

1. Worker の URL にアクセスします。
2. YouTube の URL を入力するか、API テスト用のエンドポイントを叩いてジョブを作成します。
   - 現在、UI への統合は進行中ですが、API は利用可能です。
   - `/api/download/request` に POST リクエストを送ることでダウンロードを開始できます。

### API リクエスト例 (PowerShell)

```powershell
$body = @{
  url = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
  format = "best"
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri "https://<your-worker-url>/api/download/request" -Body $body -ContentType "application/json"
```
