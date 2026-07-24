# ShieldChain 三分钟演示视频

这是 ShieldChain 比赛交付视频的可复现 Remotion 工程。成片为 1920×1080、30 fps、180 秒，画面与字幕由代码确定性生成，不依赖远程字体、网络素材或运行时密钥。

## 使用

```powershell
npm.cmd install
npm.cmd run lint
npm.cmd run dev
npx.cmd remotion render ShieldChainDemo ..\..\delivery\shieldchain-demo.mp4
npx.cmd remotion ffprobe ..\..\delivery\shieldchain-demo.mp4
```

字幕源在 `public/captions.json`，完整分镜和旁白稿在 `../../docs/delivery/video-storyboard.md`。修改字幕或场景后必须重新执行 lint、代表帧检查和完整渲染。

## 边界

视频展示的是设计、已实现能力和离线测试证据，不声称已完成 Docker 运行、真实网络、真实模型规划或真实设备路径验证。字幕不是运行日志；涉及安全结论时以仓库测试和 `delivery/manifest.json` 为准。
