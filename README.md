# CloudTrail Event Extractor

CloudTrailログからeventSourceとeventNameを抽出するスクリプトです。

# 環境
- python: 3.13

## ファイル説明

- Lambda
  - `lambda_extractor.py` - Lambda関数用スクリプト
  - `lambda_policy.json` - Lambda実行用IAMポリシー
- ローカルで動かすスクリプト
  - `cloudtrail_analyzer.py` - ローカル環境用スクリプト
  - `cloudtrail_events_bydate.py` - ローカル環境用スクリプト（日付範囲指定）


## 使用方法

### Lambda関数

Lambdaにデプロイして使用します。
15分のタイムアウト制限がありますので長期間のログ取得を行う場合は注意が必要です。

### ローカル実行

```bash
python cloudtrail_analyzer.py IAMユーザー名 [日数]
```

詳細は[Qiita記事](https://qiita.com/enumura1/items/84b06be57edf28b549b4)を参照してください。
