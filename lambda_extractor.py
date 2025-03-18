import json
import boto3
import datetime
from collections import defaultdict
import logging


# ロガーの設定
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    iam_entity = "対象のIAMユーザー/ロール名"
    days_back = 10  # 過去何日分のログか指定
    
    logger.info(f"分析開始: {iam_entity}の過去{days_back}日間のアクティビティ")
    
    # 過去X日間のログを取得
    end_time = datetime.datetime.now()
    start_time = end_time - datetime.timedelta(days=days_back)
    
    logger.info(f"期間: {start_time.isoformat()} から {end_time.isoformat()}")
    
    # CloudTrailクライアント作成
    cloudtrail = boto3.client('cloudtrail')
    
    # サービスごとのアクション収集用
    service_actions = defaultdict(set)
    total_events = 0
    
    try:
        # CloudTrailからイベント履歴を取得（ページネーション対応）
        logger.info("CloudTrailからイベント取得開始")
        paginator = cloudtrail.get_paginator('lookup_events')
        for page in paginator.paginate(
            LookupAttributes=[
                {
                    'AttributeKey': 'Username',
                    'AttributeValue': iam_entity
                }
            ],
            StartTime=start_time,
            EndTime=end_time
        ):
            page_events = page['Events']
            total_events += len(page_events)
            logger.info(f"イベント取得: {len(page_events)}件")
            
            for event in page_events:
                if 'CloudTrailEvent' in event:
                    event_details = json.loads(event['CloudTrailEvent'])
                    if "eventName" in event_details and "eventSource" in event_details:
                        service = event_details["eventSource"].split(".")[0].replace("amazonaws.com", "").replace("-", "")
                        action = event_details["eventName"]
                        # サービスごとにアクションを分類
                        service_actions[service].add(action)
        
        logger.info(f"合計イベント数: {total_events}")
        logger.info(f"検出されたサービス数: {len(service_actions)}")
        
        # サービスごとのステートメントを出力形式で作成
        result = {}
        for service, actions in service_actions.items():
            # 各サービス用のIAMアクション形式に変換
            action_list = [f"{service}:{action}" for action in actions]
            result[service] = sorted(action_list)
            logger.info(f"サービス {service}: {len(action_list)}アクション")
        
        # レスポンス
        response = {
            "アクセス分析結果": f"{iam_entity}の過去{days_back}日間のアクティビティ",
            "取得イベント数": total_events,
            "サービスごとのアクション": result
        }
        
        # 結果をログに詳細出力
        logger.info("========== 分析結果詳細 ==========")
        logger.info(json.dumps(response, ensure_ascii=False, indent=2))
        logger.info("=================================")
        
        logger.info("分析完了")
        return response
    
    except Exception as e:
        logger.error(f"エラー発生: {str(e)}")
        return {
            "エラー": str(e)
        }
