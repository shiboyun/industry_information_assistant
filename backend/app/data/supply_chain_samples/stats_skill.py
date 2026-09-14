"""统计汇总 Skill（正常样例）。

只做本地计算，不联网、不读环境变量、不碰文件系统。
用于对照：扫描器应当给出 A 级评级。
"""
import statistics

MANIFEST = {
    "name": "stats_skill",
    "version": "1.0.0",
    "description": "对给定数值序列做统计汇总",
    "permissions": {"network": [], "env": []},
    "dependencies": [],
    "reviewed": True,
}


def summarize(values):
    """返回均值、中位数与样本量。"""
    if not values:
        return {"count": 0}
    return {
        "count": len(values),
        "mean": statistics.mean(values),
        "median": statistics.median(values),
    }
