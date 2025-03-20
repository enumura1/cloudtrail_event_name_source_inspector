import json
import subprocess
import datetime
import time
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


# 実行コマンド：python cloudtrail_analyzer_daterange.py IAMユーザー名 --start-date YYYY-MM-DD --end-date YYYY-MM-DD
def main():
    # 引数の確認
    if len(sys.argv) != 6 or sys.argv[2] != "--start-date" or sys.argv[4] != "--end-date":
        print("使用方法: python cloudtrail_analyzer_daterange.py IAMユーザー名 --start-date YYYY-MM-DD --end-date YYYY-MM-DD")
        sys.exit(1)
    
    iam_entity = sys.argv[1]
    start_date = sys.argv[3]
    end_date = sys.argv[5]
    
    # 日付文字列をdatetimeオブジェクトに変換
    try:
        start_time = datetime.datetime.strptime(start_date, '%Y-%m-%d')
        end_time = datetime.datetime.strptime(end_date, '%Y-%m-%d') + datetime.timedelta(days=1) - datetime.timedelta(seconds=1)
    except ValueError:
        print("日付はYYYY-MM-DD形式で指定してください（例: 2025-01-01）")
        sys.exit(1)
    
    # 日付の妥当性チェック
    if start_time > end_time:
        print("エラー: 開始日が終了日より後になっています")
        sys.exit(1)
    
    # 固定パラメータ
    chunk_days = 10  # 10日ごとに分割処理
    api_sleep_time = 0.5  # APIリクエスト間の待機時間（秒）
    chunk_sleep_time = 30  # チャンク間の待機時間（秒）
    
    date_range = (end_time - start_time).days + 1
    print(f"分析開始: {iam_entity}の{start_date}から{end_date}までの{date_range}日間のアクティビティ")
    
    # サービスごとのイベント名収集用
    service_event_names = defaultdict(set)
    total_events = 0
    
    # 時間範囲を分割して処理
    time_chunks = []
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
            
            # API呼び出しレート制限対策のためスリープを挿入
            time.sleep(api_sleep_time)
            
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
        "アクセス分析結果": f"{iam_entity}の{start_date}から{end_date}までのアクティビティ",
        "取得イベント数": total_events,
        "サービスごとのCloudTrailイベント": result
    }
    
    # 結果を保存
    output_file = f"cloudtrail_events_{iam_entity}_{start_date}_to_{end_date}.json"
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
