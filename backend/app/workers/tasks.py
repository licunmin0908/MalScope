"""后台任务：分析任务调度。

优先使用 Celery + Redis（生产）；当未启用或 Redis 不可用时，
回退到进程内线程池执行，保证单机演示环境也能跑通完整流程。
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("workers.tasks")

_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="malscope-analysis")

# ---------------- Celery（可选） ----------------
celery_app = None
try:  # pragma: no cover - 取决于部署环境
    from celery import Celery

    celery_app = Celery(
        "malscope",
        broker=settings.REDIS_URL,
        backend=settings.REDIS_URL,
    )
    celery_app.conf.update(task_track_started=True, task_time_limit=1800)

    @celery_app.task(name="malscope.analyze")
    def analyze_task(task_id: str) -> str:
        from app.db.session import SessionLocal
        from app.services import analysis_service

        db = SessionLocal()
        try:
            analysis_service.run_task(db, task_id)
        finally:
            db.close()
        return task_id
except ImportError:  # pragma: no cover
    logger.info("未安装 Celery，使用进程内后台执行")


def _run_in_thread(task_id: str) -> None:
    from app.db.session import SessionLocal
    from app.services import analysis_service

    db = SessionLocal()
    try:
        analysis_service.run_task(db, task_id)
    except Exception as exc:  # noqa: BLE001
        logger.exception("后台分析任务异常：%s", exc)
    finally:
        db.close()


def enqueue_analysis(task_id: str) -> None:
    """将任务加入执行队列（Celery 或线程池）。"""
    if settings.USE_CELERY and celery_app is not None:
        try:
            result = analyze_task.delay(task_id)
            _save_celery_id(task_id, result.id)
            return
        except Exception as exc:  # noqa: BLE001
            logger.warning("Celery 投递失败，回退线程池：%s", exc)
    _executor.submit(_run_in_thread, task_id)


def _save_celery_id(task_id: str, celery_id: str) -> None:  # pragma: no cover
    from app.db import models
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        task = db.get(models.AnalysisTask, task_id)
        if task:
            task.celery_task_id = celery_id
            db.commit()
    finally:
        db.close()
