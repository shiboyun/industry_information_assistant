"""为已有本地账号设置安全控制台角色。

示例：
  python app/scripts/bootstrap_security_role.py --username approver --role approver
"""
import argparse
import sys
from pathlib import Path

from dotenv import load_dotenv

# 独立运行脚本时不会经过 app_main.py，因此在导入应用模块前自行定位
# backend/app 与 backend/.env，保证与后端服务使用同一套配置。
APP_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = APP_DIR.parent
sys.path.insert(0, str(APP_DIR))
load_dotenv(BACKEND_DIR / ".env")

from core.database import SessionLocal
from models.user import User


def main() -> int:
    parser = argparse.ArgumentParser(description="设置工具安全控制台角色")
    parser.add_argument("--username", required=True, help="已注册的用户名")
    parser.add_argument("--role", required=True, choices=["operator", "approver", "security_admin"])
    args = parser.parse_args()

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == args.username).first()
        if not user:
            print(f"未找到用户: {args.username}")
            return 1
        user.role = args.role
        db.commit()
        print(f"已设置 {user.username} 的角色为 {user.role}")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
