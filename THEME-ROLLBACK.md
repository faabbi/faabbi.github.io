# 2026-10-27 主题调整与回滚

修改前的版本：`eaba58728502277a9b707fc46be0e91d799278e5`。

远端备份分支：`backup/before-refresh-20261027`。该分支保留了修改前的主题、生成页面及文章备份。不要将它用作日常发布分支。

## 回到旧主题

如果刚刚合并本次 PR，尚未继续修改博客，可以在 PR 页使用 **Revert** 创建反向 PR，合并后到 Actions 手动运行 **build Gmeek**，选择 `main`。

如果之后已经写了新文章或调整配置，应保留新的内容，按文件恢复主题并检查差异：

```powershell
git switch main
git pull --ff-only
git restore --source=backup/before-refresh-20261027 -- templates static/css/mj.css static/js/mj.js
git diff --stat
```

检查 `config.json`，将 `onePageListNum` 恢复为 `15`、`themeColor` 恢复为 `#8A2BE2`，保留后来增加的其他配置。然后提交、推送，再手动运行 **build Gmeek**。完整构建会从现有 Issues 重新生成文章，避免用旧的 `docs` 覆盖后来发布的内容。新增的 `search.js` 在旧模板下不会加载。

不要使用 force push、`git reset --hard` 或直接用备份分支覆盖 `main`。

## 本次范围

- 保留 MJ、头像、原副标题、Kali 背景和文章内容。
- 调整正文、列表和移动端排版；根据后续要求保留原有标签颜色与随机流光副标题。
- 修复搜索和标签导航，保留现有 `tag.html#标签` 链接。
- 默认折叠外观设置，保留已保存的主题与背景偏好。
- 同时提交模板、静态资源和生成页面，避免下一次生成丢失主题。

`tools/render_cached.py` 只使用本地缓存文章的 HTML 更新主题，需要 Jinja2。日常发文仍使用原来的 Gmeek 工作流。

已完成 JavaScript/DOM、CSS 解析、链接和正文一致性检查。浏览器自动化因无法确认 Windows 当前 URL 被安全机制停止，因此未完成真实浏览器视觉验收。

## 同日修正

恢复原有标签配色和 20 句随机流光副标题；删除友链页的介绍、交换说明及本站信息，删除关于页的搭建说明。修正前的版本保存在 `backup/before-style-correction-20261027`。文案源自 Issues #51 和 #52，文案回滚时也需要同步恢复源 Issue。
