# backend/app/config/eval_schema.py
INDUSTRY_RESEARCH_SCHEMA = {
    "company_profile": {
        "company_name": "string",
        "founded_year": "int",
        "headquarters": "string",
        "industry_sector": "string"  # 如 "智慧交通", "新能源"
    },
    "financial_highlights": {
        "report_year": "int",
        "total_revenue": "float",  # 单位：亿元
        "net_profit": "float",
        "revenue_growth_yoy": "float",  # 百分比
        "rd_expenditure": "float"
    },
    "business_segments": [
        {
            "segment_name": "string",
            "revenue_contribution": "float",  # 百分比
            "growth_rate": "float"
        }
    ],
    "market_landscape": {
        "total_market_size": "float",
        "market_rank": "int",
        "key_competitors": ["string"]
    },
    "future_outlook": {
        "strategic_priority": "string",
        "forecast_growth": "float"
    }
}