import json
import subprocess
import datetime
from collections import defaultdict
import sys


# 個別のCloudTrailイベントを処理する関数
def process_cloudtrail_event(event, service_event_names):
    event_details = json.loads(event['CloudTrailEvent'])
    if "eventName" in event_details and "eventSource" in event_details:
        service = event_details["eventSource"].split(".")[0].replace("amazonaws.com", "").replace("-", "")
        event_name = event_details["eventName"]
        # サービスごとにイベント名を分類
        service_event_names[service].add(event_name)


# AWS CLIコマンドを実行して結果を取得する関数
def execute_aws_command(cmd):
    try:
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            raise Exception(f"AWS CLIコマンド実行エラー: {stderr}")
        
        return json.loads(stdout)
    except Exception as e:
        print(f"エラー発生: {e}")
        sys.exit(1)


# 実行コマンド：python cloudtrail_analyzer.py IAMユーザー名 [日数]
def main():
    iam_entity = sys.argv[1]
    days_back = int(sys.argv[2]) if len(sys.argv) > 2 else 90
    
    print(f"分析開始: {iam_entity}の過去{days_back}日間のアクティビティ")
    
    # 期間の設定
    end_time = datetime.datetime.now()
    start_time = end_time - datetime.timedelta(days=days_back)
    
    # サービスごとのイベント名収集用
    service_event_names = defaultdict(set)
    total_events = 0
    
    # 時間範囲を分割して処理（例：10日ごと）
    time_chunks = []
    chunk_days = 10
    chunk_start = start_time
    
    while chunk_start < end_time:
        chunk_end = min(chunk_start + datetime.timedelta(days=chunk_days), end_time)
        time_chunks.append((chunk_start, chunk_end))
        chunk_start = chunk_end
    
    print(f"期間を{len(time_chunks)}チャンクに分割して処理します")
    
    for i, (chunk_start, chunk_end) in enumerate(time_chunks):
        chunk_start_str = chunk_start.strftime("%Y-%m-%dT%H:%M:%S")
        chunk_end_str = chunk_end.strftime("%Y-%m-%dT%H:%M:%S")
        
        print(f"チャンク {i+1}/{len(time_chunks)} 処理中: {chunk_start_str} から {chunk_end_str}")
        
        # ページネーション処理
        next_token = None
        page_count = 0
        events_count = 0
        
        while True:
            # AWS CLIコマンド構築
            base_cmd = f"aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue={iam_entity} --start-time {chunk_start_str} --end-time {chunk_end_str}"
            
            if next_token:
                cmd = f"{base_cmd} --next-token {next_token}"
            else:
                cmd = base_cmd
            
            # コマンド実行とデータ取得
            data = execute_aws_command(cmd)
            
            events = data.get("Events", [])
            events_count += len(events)
            page_count += 1
            
            if page_count % 10 == 0 or len(events) > 0:
                print(f"  ページ {page_count} 処理完了: 累計 {events_count} イベント")
            
            # イベント処理
            for event in events:
                process_cloudtrail_event(event, service_event_names)
            
            # 次のトークンを取得
            next_token = data.get("NextToken")
            
            # トークンがなければループ終了
            if not next_token:
                break
                
        total_events += events_count
        print(f"チャンク {i+1} 完了: {events_count} イベント処理")
    
    # 結果作成
    result = {}
    for service, event_names in service_event_names.items():
        # CloudTrailのイベント名をサービス名とともに表示
        event_list = [f"{service}:{event_name}" for event_name in event_names]
        result[service] = sorted(event_list)
    
    response = {
        "アクセス分析結果": f"{iam_entity}の過去{days_back}日間のアクティビティ",
        "取得イベント数": total_events,
        "サービスごとのCloudTrailイベント": result
    }
    
    # 結果を保存
    current_date = end_time.strftime('%Y%m%d')
    output_file = f"cloudtrail_events_{iam_entity}_{current_date}_past{days_back}days.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(response, f, ensure_ascii=False, indent=2)
    
    print(f"分析完了: 結果を {output_file} に保存しました")
    
    # サービス数と総イベント数を表示
    print(f"検出されたサービス数: {len(result)}")
    print(f"合計イベント数: {total_events}")
    
    # サービスごとのイベント名数を表示
    for service, event_names in sorted(result.items()):
        print(f"サービス {service}: {len(event_names)}イベント")


if __name__ == "__main__":
    main()
