#!/usr/bin/env python3
"""
================================================================================
  鹰图 (Hunter) - 网络安全数据获取脚本
  官网: https://hunter.qianxin.com/

  功能说明:
    通过 Hunter 开放 API 搜索网络资产信息。
    每次搜索默认只返回 10 条数据（硬性限制），除非使用者明确使用
    --force-size 参数要求修改。

  配额说明:
    总配额 500 条，请合理规划使用。

  作者: Class01
================================================================================
"""

import argparse
import base64
import csv
import getpass
import json
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import requests

from secure_files import atomic_private_text_writer, exclusive_file_lock

# ============================================================================
#  配置区域（可修改）
# ============================================================================

# API 基础地址（无需修改，除非官方变更）
HUNTER_API_URL = "https://hunter.qianxin.com/openApi/search"

# 默认每次搜索返回条数（硬性限制 10 条）
# 除非使用者使用 --force-size 参数明确要求更改
DEFAULT_PAGE_SIZE = 10

# 总配额上限（条）
MAX_TOTAL_QUOTA = 500

# 状态文件：用于保存配额使用情况和搜索进度
STATE_FILE = "hunter_state.json"

# API 调用间隔（秒），避免触发频率限制
REQUEST_INTERVAL = 1.5


# ============================================================================
#  核心功能
# ============================================================================


def base64_url_encode(text: str) -> str:
    """将搜索语法进行 URL-safe Base64 编码（Hunter API 要求）"""
    encoded = base64.urlsafe_b64encode(text.encode("utf-8")).decode("utf-8")
    return encoded.rstrip("=")


def _write_private_json(path: str, payload):
    with atomic_private_text_writer(path) as output_file:
        json.dump(payload, output_file, ensure_ascii=False, indent=2)
        output_file.write("\n")


def _request_hunter(url, *, params, headers, timeout):
    session = requests.Session()
    session.trust_env = False
    try:
        return session.get(
            url,
            params=params,
            headers=headers,
            timeout=timeout,
        )
    finally:
        session.close()


def _csv_text(value):
    text = "" if value is None else str(value)
    if text.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


class HunterFetcher:
    """鹰图 API 数据获取器"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.state = self._load_state()

    @staticmethod
    def _encode_query(query: str) -> str:
        """Base64 URL 编码搜索查询"""
        return base64_url_encode(query)

    # ------------------------------------------------------------------
    #  状态管理
    # ------------------------------------------------------------------

    def _load_state(self) -> dict:
        """从本地文件加载配额使用状态"""
        if os.path.exists(STATE_FILE):
            try:
                with open(STATE_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                print("[!] 状态文件损坏，将重新创建")
        return {
            "used_quota": 0,  # 已使用配额（条）
            "total_quota": MAX_TOTAL_QUOTA,
            "search_history": [],  # 搜索历史记录
            "last_update": None,
        }

    def _save_state(self):
        """保存配额使用状态到本地文件"""
        self.state["last_update"] = datetime.now().isoformat()
        _write_private_json(STATE_FILE, self.state)
        print(f"[OK] 状态已保存至 {STATE_FILE}")

    @property
    def remaining_quota(self) -> int:
        """剩余可用配额（条）"""
        return self.state["total_quota"] - self.state["used_quota"]

    # ------------------------------------------------------------------
    #  API 调用
    # ------------------------------------------------------------------

    def search(
        self,
        query: str,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
        is_web: int = 1,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> dict:
        state_path = Path(STATE_FILE)
        lock_path = state_path.with_name(f".{state_path.name}.lock")
        with exclusive_file_lock(lock_path):
            self.state = self._load_state()
            return self._search_locked(
                query=query,
                page=page,
                page_size=page_size,
                is_web=is_web,
                start_time=start_time,
                end_time=end_time,
            )

    def _search_locked(
        self,
        query: str,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
        is_web: int = 1,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> dict:
        """
        执行一次搜索请求

        参数:
            query:     搜索语法（例如: ip="1.1.1.1"）
            page:      页码（从 1 开始）
            page_size: 每页条数（默认 10，硬性限制）
            is_web:    资产类型（1=web, 2=非web，默认: 1）
            start_time: 起始时间（格式: YYYY-MM-dd）
            end_time:   截止时间（格式: YYYY-MM-dd）

        返回:
            解析后的 JSON 响应字典
        """
        # 检查配额
        if page_size > self.remaining_quota:
            print(f"[!] 配额不足！剩余 {self.remaining_quota} 条，请求 {page_size} 条")
            return {"code": 429, "message": "配额不足"}

        # 默认时间范围：最近 30 天
        if not end_time:
            end_time = datetime.now().strftime("%Y-%m-%d")
        if not start_time:
            start = datetime.now() - timedelta(days=30)
            start_time = start.strftime("%Y-%m-%d")

        # 对搜索语法进行 Base64 URL 编码
        encoded_query = self._encode_query(query)

        params = {
            "api-key": self.api_key,
            "search": encoded_query,
            "page": page,
            "page_size": page_size,
            "is_web": str(is_web),
            "start_time": start_time,
            "end_time": end_time,
        }

        print(f"[*] 正在请求: 第 {page} 页 | 每页 {page_size} 条 | 查询: {query}")

        try:
            resp = _request_hunter(
                HUNTER_API_URL,
                params=params,
                headers={"Accept": "application/json"},
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()

            if data.get("code") == 200:
                # 更新配额使用情况
                actual_returned = len(data.get("data", {}).get("arr", []))
                self.state["used_quota"] += actual_returned

                # 记录搜索历史
                self.state["search_history"].append(
                    {
                        "query": query,
                        "page": page,
                        "page_size": page_size,
                        "returned": actual_returned,
                        "time": datetime.now().isoformat(),
                    }
                )
                self._save_state()

                print(
                    f"[OK] 成功获取 {actual_returned} 条数据 | "
                    f"剩余配额: {self.remaining_quota} 条"
                )
            else:
                print(f"[!] API 返回异常: {data.get('message', '未知错误')}")

            return data

        except requests.exceptions.RequestException:
            print("[ERROR] 请求失败，请检查网络或 API 凭据")
            return {"code": -1, "message": "请求失败"}

    def search_all_pages(
        self,
        query: str,
        page_size: int = DEFAULT_PAGE_SIZE,
        is_web: int = 1,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        max_pages: Optional[int] = None,
    ) -> list:
        """
        自动翻页获取所有搜索结果

        参数:
            query:      搜索语法
            page_size:  每页条数（默认 10）
            is_web:     资产类型
            start_time: 起始时间
            end_time:   截止时间
            max_pages:  最多翻页数（None=全部）

        返回:
            所有结果合并的列表
        """
        all_results = []
        page = 1

        # 先请求第一页，获取总条数
        first_resp = self.search(
            query,
            page=1,
            page_size=page_size,
            is_web=is_web,
            start_time=start_time,
            end_time=end_time,
        )

        if first_resp.get("code") != 200:
            print("[!] 首次请求失败，停止翻页")
            return all_results

        total = first_resp.get("data", {}).get("total", 0)
        arr = first_resp.get("data", {}).get("arr", [])
        all_results.extend(arr)

        if total == 0:
            print("[*] 未搜索到任何结果")
            return all_results

        total_pages = (total + page_size - 1) // page_size
        if max_pages:
            total_pages = min(total_pages, max_pages)

        print(f"[*] 共 {total} 条结果，{total_pages} 页")

        # 继续翻页
        for page in range(2, total_pages + 1):
            time.sleep(REQUEST_INTERVAL)  # 礼貌间隔

            # 检查配额
            if self.remaining_quota < page_size:
                print(f"[!] 配额不足 ({self.remaining_quota} 条)，停止翻页")
                break

            resp = self.search(
                query,
                page=page,
                page_size=page_size,
                is_web=is_web,
                start_time=start_time,
                end_time=end_time,
            )
            if resp.get("code") == 200:
                arr = resp.get("data", {}).get("arr", [])
                all_results.extend(arr)
            else:
                print("[!] 翻页失败，提前停止")
                break

        print(f"[OK] 翻页完成，共获取 {len(all_results)} 条数据")
        return all_results

    # ------------------------------------------------------------------
    #  数据导出
    # ------------------------------------------------------------------

    def export_json(self, data: list, filename: str = "hunter_results.json"):
        """导出为 JSON 文件"""
        _write_private_json(filename, data)
        print(f"[OK] 已导出 JSON: {filename} ({len(data)} 条)")

    def export_csv(self, data: list, filename: str = "hunter_results.csv"):
        """导出为 CSV 文件"""
        if not data:
            print("[!] 无数据可导出")
            return

        # 从第一条数据提取字段名
        fieldnames = list(data[0].keys())
        with atomic_private_text_writer(
            filename, encoding="utf-8-sig", newline=""
        ) as f:
            writer = csv.writer(f)
            writer.writerow(_csv_text(fieldname) for fieldname in fieldnames)
            for row in data:
                writer.writerow(
                    _csv_text(row.get(fieldname)) for fieldname in fieldnames
                )
        print(f"[OK] 已导出 CSV: {filename} ({len(data)} 条)")

    def print_results(self, data: list):
        """在终端打印结果"""
        if not data:
            print("[*] 无数据")
            return

        print(f"\n{'=' * 80}")
        print(f"共 {len(data)} 条结果:")
        print(f"{'=' * 80}")
        for i, item in enumerate(data, 1):
            print(f"\n--- 第 {i} 条 ---")
            for key, value in item.items():
                print(f"  {key}: {value}")
        print(f"{'=' * 80}\n")


# ============================================================================
#  命令行入口
# ============================================================================


def parse_args():
    parser = argparse.ArgumentParser(
        description="鹰图 (Hunter) 数据获取工具 - Class01",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 设置 API Key（首次使用）
  python hunter_fetcher.py --set-key

  # 执行单次搜索（默认每页 10 条）
  python hunter_fetcher.py --search 'ip="1.1.1.1"'

  # 翻页获取所有结果
  python hunter_fetcher.py --search 'domain="example.com"' --all-pages

  # 导出为 CSV
  python hunter_fetcher.py --search 'port="80"' --all-pages --export csv

  # 查看配额状态
  python hunter_fetcher.py --status

  # 强制修改每页条数（需使用者明确确认）
  python hunter_fetcher.py --search 'ip="1.1.1.1"' --force-size --page-size 50

注意事项:
  1. 每次搜索默认仅返回 10 条（硬性限制）
  2. 修改 page-size 必须同时使用 --force-size 参数
  3. 总配额 500 条，用完即止
  4. 请遵循鹰图平台使用条款
        """,
    )

    # API Key 配置
    parser.add_argument(
        "--set-key",
        action="store_true",
        help="安全提示输入 API Key 并保存到本地配置文件",
    )
    parser.add_argument(
        "--key",
        action="store_true",
        help="安全提示输入临时 API Key（不保存）",
    )

    # 搜索参数
    parser.add_argument(
        "--search",
        "-s",
        type=str,
        metavar="QUERY",
        help='搜索语法（例如: ip="1.1.1.1"）',
    )
    parser.add_argument(
        "--page",
        "-p",
        type=int,
        default=1,
        help="页码（默认: 1）",
    )
    parser.add_argument(
        "--page-size",
        "-n",
        type=int,
        default=DEFAULT_PAGE_SIZE,
        help=f"每页条数（默认: {DEFAULT_PAGE_SIZE}，需配合 --force-size 修改）",
    )
    parser.add_argument(
        "--force-size",
        action="store_true",
        help="强制修改每页条数（必须明确使用此参数才能修改 page-size）",
    )
    parser.add_argument(
        "--all-pages",
        action="store_true",
        help="自动翻页获取所有结果",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=None,
        help="最多翻页数（默认: 不限）",
    )
    parser.add_argument(
        "--is-web",
        type=int,
        default=1,
        choices=[1, 2],
        help="资产类型: 1=web, 2=非web（默认: 1）",
    )
    parser.add_argument(
        "--start-time",
        type=str,
        help="起始时间 (YYYY-MM-dd，默认: 30天前)",
    )
    parser.add_argument(
        "--end-time",
        type=str,
        help="截止时间 (YYYY-MM-dd，默认: 今天)",
    )

    # 导出选项
    parser.add_argument(
        "--export",
        "-e",
        type=str,
        choices=["json", "csv"],
        default=None,
        help="导出格式 (json 或 csv)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="导出文件名（默认: hunter_results.json/csv）",
    )

    # 状态
    parser.add_argument(
        "--status",
        action="store_true",
        help="查看当前配额使用状态",
    )

    # 显示
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="静默模式，只输出数据不输出过程信息",
    )

    return parser.parse_args()


def main():
    args = parse_args()
    config_file = "hunter_config.json"

    # ------------------------------------------------------------------
    #  功能 1: 设置 API Key
    # ------------------------------------------------------------------
    if args.set_key:
        api_key = getpass.getpass("Hunter API Key: ").strip()
        if not api_key:
            print("[!] API Key 不能为空")
            return 1
        config = {"api_key": api_key}
        _write_private_json(config_file, config)
        print(f"[OK] API Key 已保存至 {config_file}（权限: 600）")
        return

    # ------------------------------------------------------------------
    #  功能 2: 查看状态
    # ------------------------------------------------------------------
    if args.status:
        fetcher = HunterFetcher(api_key="")  # 先临时创建以加载状态
        state = fetcher._load_state()
        print(f"\n{'=' * 50}")
        print("  鹰图 Hunter - 配额使用状态")
        print(f"{'=' * 50}")
        print(f"  总配额:      {state['total_quota']} 条")
        print(f"  已使用:      {state['used_quota']} 条")
        print(f"  剩余:        {state['total_quota'] - state['used_quota']} 条")
        print(f"  搜索次数:    {len(state['search_history'])} 次")
        if state["last_update"]:
            print(f"  最后更新:    {state['last_update']}")
        print(f"  状态文件:    {STATE_FILE}")
        print(f"{'=' * 50}")

        if state["search_history"]:
            print("\n  最近 5 次搜索:")
            for record in state["search_history"][-5:]:
                print(f"    · {record['query']} → 获取 {record['returned']} 条")
        return

    # ------------------------------------------------------------------
    #  功能 3: 执行搜索
    # ------------------------------------------------------------------
    if not args.search:
        print("[!] 请提供搜索语法，使用 --search 参数")
        print("    例如: python hunter_fetcher.py --search 'ip=\"1.1.1.1\"'")
        print("    使用 --help 查看完整帮助")
        sys.exit(1)

    # --- 加载 API Key ---
    api_key = None
    if args.key:
        api_key = getpass.getpass("Hunter API Key: ").strip()
    if not api_key:
        api_key = os.getenv("HUNTER_API_KEY")
    if not api_key:
        if os.path.exists(config_file):
            try:
                with open(config_file, "r") as f:
                    config = json.load(f)
                api_key = config.get("api_key", "")
            except (json.JSONDecodeError, IOError):
                pass

    if not api_key:
        print("[!] 未设置 API Key！")
        print("    请先运行: python hunter_fetcher.py --set-key")
        print("    或使用:   python hunter_fetcher.py --key --search ...")
        sys.exit(1)

    # --- 校验 page_size 硬性限制 ---
    if args.page_size != DEFAULT_PAGE_SIZE and not args.force_size:
        print(f"\n{'=' * 60}")
        print(f"  [BLOCKED] 每页条数被限制为 {DEFAULT_PAGE_SIZE} 条（硬性限制）")
        print(f"  你请求了 page-size={args.page_size}，但未使用 --force-size 参数。")
        print(f"  如需修改请确认后重新运行: --page-size {args.page_size} --force-size")
        print(f"{'=' * 60}\n")
        # 强制回退到默认值
        args.page_size = DEFAULT_PAGE_SIZE

    if args.force_size and args.page_size != DEFAULT_PAGE_SIZE:
        print(f"\n{'!' * 60}")
        print(
            f"  [WARNING] 你已使用 --force-size，将 page-size 修改为 {args.page_size}"
        )
        print(
            f"  注意: 这将加速消耗配额（剩余 {MAX_TOTAL_QUOTA - HunterFetcher(api_key=api_key)._load_state()['used_quota']} 条）"
        )
        print(f"{'!' * 60}\n")
        # 需要用户确认
        try:
            confirm = input("  确认继续? (yes/no): ").strip().lower()
            if confirm not in ("yes", "y"):
                print("[!] 已取消")
                sys.exit(0)
        except (EOFError, KeyboardInterrupt):
            print("\n[!] 已取消")
            sys.exit(0)

    # --- 执行搜索 ---
    fetcher = HunterFetcher(api_key)

    if args.all_pages:
        results = fetcher.search_all_pages(
            query=args.search,
            page_size=args.page_size,
            is_web=args.is_web,
            start_time=args.start_time,
            end_time=args.end_time,
            max_pages=args.max_pages,
        )
    else:
        resp = fetcher.search(
            query=args.search,
            page=args.page,
            page_size=args.page_size,
            is_web=args.is_web,
            start_time=args.start_time,
            end_time=args.end_time,
        )
        data = resp.get("data")
        results = data.get("arr", []) if data else []

    # --- 输出结果 ---
    if not args.quiet:
        fetcher.print_results(results)

    # --- 导出 ---
    if args.export and results:
        filename = args.output or f"hunter_results.{args.export}"
        if args.export == "json":
            fetcher.export_json(results, filename)
        elif args.export == "csv":
            fetcher.export_csv(results, filename)

    # 简要输出总结
    total = len(results)
    print(f"\n[完成] 获取 {total} 条结果 | 剩余配额: {fetcher.remaining_quota} 条")


if __name__ == "__main__":
    raise SystemExit(main())
