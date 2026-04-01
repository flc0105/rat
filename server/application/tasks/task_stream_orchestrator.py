from server.application.tasks.task_status import TaskStreamSummary


class WebTaskStreamOrchestrator:
    """
    Web 任务结果流编排器。

    职责：
    - 消费结果流
    - 汇总统一终态
    - 协调 task store / event publisher / history recorder
    """

    def __init__(self, task_store, event_publisher, history_recorder):
        self.task_store = task_store
        self.event_publisher = event_publisher
        self.history_recorder = history_recorder

    def run_stream(self, conn, task_id: str, command: str, result_iter):
        """
        统一执行 Web 任务结果流：
        - 消费生成器输出
        - 记录任务分片
        - 推送 SSE 结果
        - 统一异常处理
        - 统一结束收尾
        """
        client_id = conn.info.get('id')
        summary = TaskStreamSummary()

        try:
            for status, result in result_iter:
                text = '' if result is None else str(result)

                self.event_publisher.publish_task_result(
                    task_id,
                    client_id,
                    command,
                    status,
                    text
                )
                self.history_recorder.append_output(conn, task_id, status, text)
                summary.record_chunk(status, text)

        except Exception as e:
            text = str(e)
            summary.mark_exception()

            self.event_publisher.publish_task_result(
                task_id,
                client_id,
                command,
                0,
                text
            )
            self.history_recorder.append_output(conn, task_id, 0, text)

        finally:
            task = self.task_store.get_task(task_id) or {}
            final_status = summary.resolve_final_status(
                cancel_requested=bool(task.get('cancel_requested'))
            )

            self.task_store.finish_task(
                task_id,
                ok=summary.is_success(),
                final_status=final_status
            )

            self.history_recorder.finalize(
                conn,
                task_id,
                ok=final_status == 'success'
            )

            self.event_publisher.publish_task_complete(
                task_id,
                client_id,
                command
            )


