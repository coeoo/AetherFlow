# 模块实现设计模板

> 使用本模板编写 `docs/design/` 下的长期实现设计。模板中的每一节都应基于
> 当前代码事实填写；如果只是未来设想，必须标注为 `设计目标`。

## 1. 模块定位

- 模块名称：
- 所属边界：
  - Graph Orchestration
  - Runtime
  - Tool
  - Skill
  - Decision
  - Evidence
  - API
  - Frontend
- 解决的问题：
- 不解决的问题：
- 当前实现状态：

## 2. 代码入口

主入口：

- `path/to/file.py::function_name`

直接调用方：

- `path/to/caller.py::function_name`

直接依赖：

- `path/to/dependency.py::function_name`

## 3. 输入契约

外部输入：

- 请求参数：
- 任务 payload：
- 环境变量：
- feature flag：

内部输入：

- 状态字段：
- 数据库读取：
- 文件或 prompt：

## 4. 输出契约

返回值：

- 类型：
- 字段：

状态变更：

- 字段：
- 写入时机：

持久化写入：

- 表：
- 字段：
- 触发条件：

日志和诊断：

- 正常日志：
- 异常日志：
- 脱敏要求：

## 5. 核心数据结构

列出 TypedDict、dataclass、ORM model、前端 DTO 或 JSON payload。

每个结构至少说明：

- 字段名。
- 类型。
- 含义。
- 谁写入。
- 谁读取。
- 是否允许为空。

## 6. 主流程

用顺序步骤描述正常路径：

1. 接收输入。
2. 构建内部状态。
3. 调用核心能力。
4. 写入结果。
5. 返回或收口。

如有状态机，补充状态流转：

```text
state_a -> state_b -> state_c
```

如有图编排，补充节点和路由：

```text
START -> node_a -> node_b -> END
```

## 7. 分支、错误与降级

必须覆盖：

- 参数缺失。
- 外部服务失败。
- 非法响应。
- 预算耗尽。
- 空结果。
- 可重试错误。
- 不可重试错误。

每类错误说明：

- 检测位置。
- 错误标识。
- 记录方式。
- 对用户或上游的输出。
- 是否 fallback。

## 8. 测试映射

单元测试：

- `backend/tests/test_xxx.py::test_name`

集成测试：

- `backend/tests/test_xxx.py::test_name`

验收或回归命令：

```bash
timeout 60s ./.venv/bin/python -m pytest path/to/test.py -q
```

如无法直接测试，必须说明原因和人工核对方式。

## 9. 源码复刻清单

如果源码丢失，按以下顺序重建：

1. 先定义数据结构和状态字段。
2. 再实现主入口函数。
3. 再接入调用方。
4. 再补错误和降级。
5. 再补持久化写入。
6. 最后补测试和验收脚本。

复刻完成后必须验证：

- 主流程测试。
- 错误分支测试。
- 回归样本。
- 文档和代码入口一致。

## 10. 已知差距

列出当前设计或实现的不足：

- 差距：
- 影响：
- 后续建议：
