# 本番 Firebase Auth 移行 手順書

> グループウェア（groupware.html）のログインを Firebase Authentication 方式へ安全に移行するための手順。
> テスト環境（groupware-test.html）で全工程を検証済み（2026-06-10）。
> 目的：① Firestoreが誰でも読み書きできる問題 ② パスワードが平文保存されている問題 の両方を解決する。

---

## ★ 事前調査の結果（2026-06-11 実施・実行前に必読）

- **本番ロールバック点**：groupware.html は commit `01d0181`（ローカル＝リモート同期済み）
- **本番Authドメイン**：`gw.dainichi.local` を使う（welpia/国保連は `welbe.dainichi.local` を既に使用中。別アプリ・別ユーザーなので名前空間を分ける）
- **要事前対応（6文字未満パスワード）**：Firebase Authは6文字以上必須。下記2名は移行前にパスワードを6文字以上へ変更が必要：
  - narita（現 `BL001`）
  - nakasima（現 `BL002`）
- **他アプリへの影響調査結果**：
  - welpia.html（国保連・`kokuhoren_data`）→ **既にFirebase Authで運用中**（signIn/createUser/onAuthStateChanged実装済み）。よって `kokuhoren_data` を auth必須に締めても安全。
  - shift_management.html / shift_management_welpia.html → gw2data等を使っておらず**影響なし**。
  - **gw2data / gw_backups を no-auth で触っているのは groupware.html だけ** → ここを移行すれば本番の穴は塞がる。

---

## 0. 前提・確認済みのこと

- テスト環境で以下を実証済み：
  - Auth ログイン（ID→`<id>@dainichi-test.local` 形式に自動変換）
  - 平文→ハッシュ化への「遅延移行」（各自が1回ログインすると自動でAuth登録）
  - フォールバック（Auth未登録でも従来方式でログインでき、誰も締め出さない）
  - `gw2data_test` を「ログイン必須」にしてもログイン中は全機能が正常動作
- Firebase コンソール：Authentication の「メール/パスワード」は **すでに有効**
- 本番ドメインは `dainichi-test.local` ではなく **`dainichi.local`** を使う（テストと混ざらないよう変える）

---

## 1. 実施タイミング

- **全社員が使っていない時間帯**（早朝・休業日など）に着手
- 所要：実作業 合計30分〜1時間（数回に分割可）

---

## 2. 事前準備（切り戻しの保険）★必ず最初に

1. **コミット**して現在のコードを記録（戻せるようにする）
   ```
   git add -A && git commit -m "Auth移行前の状態を記録"
   ```
2. グループウェアにログイン →「🛡️ バックアップ」→ **「💾 バックアップをダウンロード」** でJSONを手元/USBに保存
3. Firebase コンソール → Firestore →「ルール」→ 現在のルールをコピーしてメモ（戻す用）

---

## 3. 本番コードに Auth を反映（見た目・操作は何も変わらない）

groupware-test.html で実装済みの内容を groupware.html に移植する。具体的には：

1. `<head>` に auth スクリプトを追加：
   ```html
   <script src="https://www.gstatic.com/firebasejs/9.23.0/firebase-auth-compat.js"></script>
   ```
2. `_db`/`_storage` 初期化の直後に追加：
   ```js
   const _auth = firebase.auth();
   const _AUTH_DOMAIN = 'dainichi.local';            // ★本番は dainichi.local
   function _authEmail(loginId){ return String(loginId).toLowerCase()+'@'+_AUTH_DOMAIN; }
   ```
3. `doLogin()` を test 版と同じ「①Auth照合→②従来方式フォールバック→③遅延移行」の async 実装に置き換える
   （groupware-test.html の doLogin をそのままコピー。`_AUTH_DOMAIN` だけ本番値）
4. 構文チェック → コミット → プッシュ
   - この時点では **ルールはまだ `if true` のまま**。見た目も操作も一切変わらない。
   - パスワード6文字未満（例：narita=BL001 等）はAuth登録されない→④で対応

---

## 4. 全員を Auth に移行（ルール強化の「前」に必ず完了させる）

**方法A：自然移行（おすすめ・手間ゼロ・ダウンタイムなし）**
- コード反映後、数日かけて各自が普段通りログイン→自動でAuth登録される
- Firebase コンソール → Authentication → ユーザー で、`<id>@dainichi.local` が**全員分そろう**まで待つ

**パスワード6文字未満の人の対応（narita/nakasima 等）**
- Firebase は6文字以上が必須。`BL001`(5文字)等はAuth登録できない
- 対応：ユーザー管理でその人のパスワードを6文字以上に変更してから本人がログイン
  （または管理者が「ユーザーを追加」でコンソールから直接登録）

**移行状況の確認**
- Authentication のユーザー数が、稼働中ユーザー数と一致すればOK

---

## 5. Firestore ルールを「ログイン必須」に強化（最後の仕上げ・5分）

★ 4で全員のAuth登録が完了してから実施すること（未登録の人がいると締め出される）

Firebase コンソール → Firestore →「ルール」で、本番の `gw2data` と `gw_backups` を変更：

```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /gw2data/{document=**} {
      allow read, write: if request.auth != null;     // ← if true から変更
    }
    match /gw_backups/{document=**} {
      allow read, write: if request.auth != null;     // ← if true から変更
    }
    match /gw2data_test/{document=**} {
      allow read, write: if request.auth != null;
    }
    match /gw_backups_test/{document=**} {
      allow read, write: if request.auth != null;
    }
    match /kokuhoren_data/{document=**} {
      allow read, write: if request.auth != null;     // 国保連も使用中なら同様に。要確認
    }
    match /{document=**} {
      allow read, write: if request.auth != null;
    }
  }
}
```
→「公開」

※ kokuhoren_data（国保連請求）も別アプリで使用中。そのアプリがAuth未対応なら `if true` のまま残すか、同様にAuth対応が必要。**先に確認すること。**

---

## 6. 動作確認

1. 本番にログイン（admin・一般ユーザー数名）→ 全機能が見える/使えるか
2. シークレットウィンドウで本番URLを開く（未ログイン）→「接続失敗」になればOK（部外者ブロック成功）

---

## 7. 切り戻し（万一おかしくなったら）

- **ルールを戻す**：Firebase コンソール →「ルール」→ 履歴から1つ前を選んで再公開（即時）
- **コードを戻す**：`git revert` または GitHub で前のコミットへ
- **データを戻す**：バックアップから復元（2でDLしたJSON、または「この日に戻す」）

---

## 注意点まとめ

- ルール強化（5）は「全員Auth登録済み（4完了）」が絶対条件
- パスワード6文字未満の人を先に解消
- kokuhoren_data（国保連）の扱いを事前確認
- 本番ドメインは `dainichi.local`（テストの `dainichi-test.local` と分ける）
- 移行後はパスワードを後から平文で見られない→「忘れたらリセット」運用に変わる

---

最終更新：2026-06-10（テスト環境で全工程検証済み）
