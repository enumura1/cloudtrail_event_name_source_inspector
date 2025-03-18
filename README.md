# CloudTrail Event Extractor

CloudTrailログからeventSourceとeventNameを抽出するスクリプトです。

## ファイル説明

- `lambda_extractor.py` - Lambda関数用スクリプト
- `cloudtrail_analyzer.py` - ローカル環境用スクリプト
- `lambda_policy.json` - Lambda実行用IAMポリシー

## 使用方法

### Lambda関数

Lambdaにデプロイして使用します。
15分のタイムアウト制限がありますので長期間のログ取得を行う場合は注意が必要です。

### ローカル実行

```bash
python cloudtrail_analyzer.py IAMユーザー名 [日数]
```

詳細は[Qiita記事](https://qiita.com/enumura1/items/84b06be57edf28b549b4)を参照してください。
