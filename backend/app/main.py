"""MalScope 后端应用入口。

启动时初始化数据库与初始数据；挂载全部 API；若前端已构建则一并托管。
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.v1.router import api_router
from app.core.config import PROJECT_DIR, settings
from app.core.logging import get_logger, setup_logging
from app.db.session import init_db

setup_logging()
logger = get_logger("main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("启动 %s v%s", settings.APP_NAME, settings.APP_VERSION)
    init_db()
    logger.info("数据库初始化完成，沙箱驱动=%s", settings.SANDBOX_DRIVER)
    yield
    logger.info("服务已停止")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "面向恶意代码分析的智能分析平台后端：静态分析引擎、动态沙箱分析引擎、"
        "威胁情报与 IOC 提取、样本库与 RBAC 权限审计。"
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.API_PREFIX)


@app.get("/health", tags=["系统"], summary="健康检查")
def health():
    return {
        "status": "ok",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "sandbox_driver": settings.SANDBOX_DRIVER,
    }


# 托管前端构建产物（若存在）
_FRONTEND_DIST = PROJECT_DIR / "frontend" / "dist"
if _FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=str(_FRONTEND_DIST / "assets")), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str):
        index = _FRONTEND_DIST / "index.html"
        target = _FRONTEND_DIST / full_path
        if full_path and target.is_file():
            return FileResponse(str(target))
        if index.exists():
            return FileResponse(str(index))
        return JSONResponse({"detail": "前端未构建"}, status_code=404)


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
