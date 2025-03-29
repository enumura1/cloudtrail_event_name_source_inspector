import json
import subprocess
import datetime
import time
from collections import defaultdict
import sys
import random
import os


# 個別のCloudTrailイベントを処理する関数
def process_cloudtrail_event(event, service_event_names):
    event_details = json.loads(event['CloudTrailEvent'])
    if "eventName" in event_details and "eventSource" in event_details:
        service = event_details["eventSource"].split(".")[0].replace("amazonaws.com", "").replace("-", "")
        event_name = event_details["eventName"]
        # サービスごとにイベント名を分類
        service_event_names[service].add(event_name)


# AWS CLIコマンドを実行して結果を取得する関数 (エラーハンドリング強化版)
def execute_aws_command(cmd, max_retries=3, retry_delay=2):
    retries = 0
    while retries <= max_retries:
        try:
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                if "ThrottlingException" in stderr or "RequestLimitExceeded" in stderr:
                    retries += 1
                    wait_time = retry_delay * (2 ** retries) + random.uniform(0, 1)
                    print(f"スロットリング検出。{wait_time:.2f}秒後に再試行します。({retries}/{max_retries})")
                    time.sleep(wait_time)
                    continue
                else:
                    raise Exception(f"AWS CLIコマンド実行エラー: {stderr}")
            
            return json.loads(stdout)
        
        except Exception as e:
            print(f"コマンド実行中にエラーが発生: {e}")
            retries += 1
            if retries <= max_retries:
                time.sleep(retry_delay * retries)
            else:
                raise
    
    raise Exception(f"最大再試行回数({max_retries})に達しました。")


# CloudTrailイベントを取得する関数 (マルチリージョン対応)
def get_cloudtrail_events(iam_entity, chunk_start_str, chunk_end_str, regions, max_items=1000):
    all_events = []
    
    for region in regions:
        print(f"リージョン {region} の処理を開始...")
        starting_token = None
        
        while True:
            # AWS CLIコマンド構築
            base_cmd = f"aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue={iam_entity} --start-time {chunk_start_str} --end-time {chunk_end_str} --region {region} --max-items {max_items}"
            
            if starting_token:
                cmd = f"{base_cmd} --starting-token {starting_token}"
            else:
                cmd = base_cmd
            
            try:
                # コマンド実行とデータ取得
                data = execute_aws_command(cmd)
                
                # イベントの追加
                events = data.get("Events", [])
                all_events.extend(events)
                
                print(f"  リージョン {region}: {len(events)} イベント取得")
                
                # 次のトークンを取得
                starting_token = data.get("NextToken")
                
                # スロットリング回避、すりーぷ
                wait_time = 2
                time.sleep(wait_time)
                
                # トークンがなければリージョンの処理終了
                if not starting_token:
                    break
                    
            except Exception as e:
                print(f"警告: リージョン {region} での処理中にエラーが発生: {e}")
                # エラーが発生しても他のリージョンは続行
                break
    
    return all_events


# 実行コマンド：python cloudtrail_analyzer_daterange.py IAMユーザー名 --start-date YYYY-MM-DD --end-date YYYY-MM-DD [--regions region1,region2,...]
def main():
    # 引数の確認
    if len(sys.argv) < 6:
        print("使用方法: python cloudtrail_analyzer_daterange.py IAMユーザー名 --start-date YYYY-MM-DD --end-date YYYY-MM-DD [--regions region1,region2,...]")
        sys.exit(1)
    
    iam_entity = sys.argv[1]
    
    # 引数のパース
    start_date = None
    end_date = None
    regions = ["ap-northeast-1", "us-east-1"]
    
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--start-date" and i + 1 < len(sys.argv):
            start_date = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--end-date" and i + 1 < len(sys.argv):
            end_date = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--regions" and i + 1 < len(sys.argv):
            regions = sys.argv[i + 1].split(",")
            i += 2
        else:
            print(f"不明なオプション: {sys.argv[i]}")
            i += 1
    
    if not start_date or not end_date:
        print("開始日と終了日を指定してください")
        sys.exit(1)
    
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
    chunk_days = 7 
    max_items = 1000
    
    date_range = (end_time - start_time).days + 1
    print(f"分析開始: {iam_entity}の{start_date}から{end_date}までの{date_range}日間のアクティビティ")
    print(f"検索対象リージョン: {', '.join(regions)}")
    
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
        
        # CloudTrailイベントの取得（マルチリージョン対応）
        events = get_cloudtrail_events(iam_entity, chunk_start_str, chunk_end_str, regions, max_items)
        
        events_count = len(events)
        total_events += events_count
        
        # イベント処理
        for event in events:
            process_cloudtrail_event(event, service_event_names)
        
        print(f"チャンク {i+1} 完了: {events_count} イベント処理")
        
        # チャンク間の待機時間
        if i < len(time_chunks) - 1:
            wait_time = 2
            print(f"{wait_time}秒間待機してから次のチャンクを処理します...")
            time.sleep(wait_time)
    
    # 結果
    result = {}
    for service, event_names in service_event_names.items():
        # イベント名, サービス名を一緒に格納
        event_list = [f"{service}:{event_name}" for event_name in event_names]
        result[service] = sorted(event_list)
    
    response = {
        "アクセス分析結果": f"{iam_entity}の{start_date}から{end_date}までのアクティビティ",
        "検索対象リージョン": regions,
        "取得イベント数": total_events,
        "サービスごとのCloudTrailイベント": result
    }
    
    # 結果を保存（日時を追加して重複を避ける）
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
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
