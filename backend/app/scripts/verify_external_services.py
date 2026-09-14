"""外部服务配置与可选连通性检查。

默认模式不发送任何网络请求，不会消耗 API 额度：
    python app/scripts/verify_external_services.py

只有显式传入 --live 才会执行最小外部请求：
    python app/scripts/verify_external_services.py --live --services dashscope,bocha

DocMind 和招投标服务不会被自动调用，因为前者可能创建文档解析任务，后者
可能消耗查询额度。请在网站对应页面手动使用一份测试数据进行验证。
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Iterable

import aiohttp
from dotenv import dotenv_values


ENV_PATH = Path(__file__).resolve().parents[2] / ".env"

SERVICES = {
    "dashscope": {
        "keys": ("DASHSCOPE_API_KEY",),
        "feature": "普通聊天、Embedding、重排序、记忆、深度研究模型",
    },
    "bocha": {
        "keys": ("BOCHA_API_KEY",),
        "feature": "深度研究联网搜索、行业新闻采集",
    },
    "serper": {
        "keys": ("SERPER_API_KEY",),
        "feature": "普通聊天联网搜索",
    },
    "docmind": {
        "keys": ("DOCMIND_ACCESS_KEY_ID", "DOCMIND_ACCESS_KEY_SECRET"),
        "feature": "高级文档解析",
    },
    "juhe": {
        "keys": ("JUHE_STOCK_API_KEY",),
        "feature": "实时股票行情",
    },
    "bidding": {
        "keys": ("BID_APP_CODE",),
        "feature": "招投标数据查询与采集",
    },
}


def configured(config: dict[str, str | None], keys: Iterable[str]) -> bool:
    return all((config.get(key) or "").strip() for key in keys)


def print_configuration(config: dict[str, str | None]) -> None:
    print(f"环境文件：{ENV_PATH}")
    print("\n配置检查（不发送网络请求）：")
    for service, details in SERVICES.items():
        state = "已配置" if configured(config, details["keys"]) else "未配置"
        print(f"- {service:<10} {state}：{details['feature']}")


async def request_json(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    **kwargs: object,
) -> tuple[int, str]:
    async with session.request(method, url, **kwargs) as response:
        body = await response.text()
        return response.status, body[:300]


async def check_dashscope(session: aiohttp.ClientSession, config: dict[str, str | None]) -> bool:
    url = f"{config.get('DASHSCOPE_BASE_URL', '').rstrip('/')}/chat/completions"
    payload = {
        "model": config.get("OPENAI_MODEL") or "qwen3-max",
        "messages": [{"role": "user", "content": "Reply with OK."}],
        "max_tokens": 5,
    }
    status, body = await request_json(
        session,
        "POST",
        url,
        headers={"Authorization": f"Bearer {config['DASHSCOPE_API_KEY']}"},
        json=payload,
    )
    print(f"dashscope: HTTP {status}" + ("，可用" if status == 200 else f"，失败：{body}"))
    return status == 200


async def check_bocha(session: aiohttp.ClientSession, config: dict[str, str | None]) -> bool:
    status, body = await request_json(
        session,
        "POST",
        "https://api.bochaai.com/v1/web-search",
        headers={"Authorization": f"Bearer {config['BOCHA_API_KEY']}"},
        json={"query": "ChallengeCupBase connectivity test", "count": 1},
    )
    print(f"bocha: HTTP {status}" + ("，可用" if status == 200 else f"，失败：{body}"))
    return status == 200


async def check_serper(session: aiohttp.ClientSession, config: dict[str, str | None]) -> bool:
    status, body = await request_json(
        session,
        "POST",
        "https://google.serper.dev/search",
        headers={"X-API-KEY": config["SERPER_API_KEY"] or ""},
        json={"q": "ChallengeCupBase connectivity test", "num": 1},
    )
    print(f"serper: HTTP {status}" + ("，可用" if status == 200 else f"，失败：{body}"))
    return status == 200


async def check_juhe(session: aiohttp.ClientSession, config: dict[str, str | None]) -> bool:
    status, body = await request_json(
        session,
        "GET",
        "http://web.juhe.cn/finance/stock/hs",
        params={"gid": "sh601009", "key": config["JUHE_STOCK_API_KEY"] or ""},
    )
    print(f"juhe: HTTP {status}" + ("，请求成功" if status == 200 else f"，失败：{body}"))
    return status == 200


LIVE_CHECKS = {
    "dashscope": check_dashscope,
    "bocha": check_bocha,
    "serper": check_serper,
    "juhe": check_juhe,
}


async def run_live_checks(config: dict[str, str | None], services: list[str]) -> int:
    timeout = aiohttp.ClientTimeout(total=45)
    failures = 0
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for service in services:
            if service in {"docmind", "bidding"}:
                print(f"{service}: 未自动调用。请在网站页面执行一次测试操作。")
                continue
            if not configured(config, SERVICES[service]["keys"]):
                print(f"{service}: 未配置，跳过联网检查。")
                failures += 1
                continue
            try:
                if not await LIVE_CHECKS[service](session, config):
                    failures += 1
            except (aiohttp.ClientError, asyncio.TimeoutError) as error:
                print(f"{service}: 网络请求失败：{type(error).__name__}")
                failures += 1
    return failures


def parse_services(value: str) -> list[str]:
    selected = list(SERVICES) if value == "all" else [item.strip() for item in value.split(",") if item.strip()]
    unknown = sorted(set(selected) - set(SERVICES))
    if unknown:
        raise argparse.ArgumentTypeError(f"未知服务：{', '.join(unknown)}")
    return selected


def main() -> int:
    parser = argparse.ArgumentParser(description="检查 ChallengeCupBase 外部服务配置")
    parser.add_argument("--live", action="store_true", help="执行最小联网检查，可能消耗 API 额度")
    parser.add_argument(
        "--services",
        type=parse_services,
        default=list(SERVICES),
        help="逗号分隔的服务名：dashscope,bocha,serper,docmind,juhe,bidding；默认 all",
    )
    args = parser.parse_args()

    if not ENV_PATH.exists():
        print(f"未找到环境文件：{ENV_PATH}", file=sys.stderr)
        return 2

    config = dotenv_values(ENV_PATH)
    print_configuration(config)
    if not args.live:
        print("\n未传入 --live：未发送任何外部 API 请求。")
        return 0

    print("\n开始最小联网检查：")
    return 1 if asyncio.run(run_live_checks(config, args.services)) else 0


if __name__ == "__main__":
    raise SystemExit(main())
