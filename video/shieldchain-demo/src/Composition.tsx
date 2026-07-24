import { AbsoluteFill, Easing, interpolate, Sequence, useCurrentFrame } from "remotion";
import { CaptionOverlay } from "./CaptionOverlay";

const sceneFrames = 540;
type Scene = { kicker: string; title: string; subtitle: string; points: string[]; accent: string };
const scenes: Scene[] = [
  { kicker: "SHIELDCHAIN / 盾链智御", title: "让智能体的每一步都可控", subtitle: "可授权 · 可验证 · 可审计的安全运营闭环", points: ["网络安全智能体比赛交付", "离线可复现 · 边界诚实"], accent: "#3d8dff" },
  { kicker: "WHY", title: "真正的难点不是分析，而是执行", subtitle: "上下文、动作与验证之间存在三道断层", points: ["证据与权限易丢失", "模型直连设备风险失控", "动作完成不等于风险消失"], accent: "#ff9f43" },
  { kicker: "ARCHITECTURE", title: "语义能力与确定性控制分层", subtitle: "React → FastAPI → 领域闭环 → SQLite / Alembic", points: ["模型负责语义", "代码负责权限、状态和执行", "外部能力全部经 adapter 接入"], accent: "#6dcbf4" },
  { kicker: "CLOSED LOOP", title: "证据—决策—动作—验证", subtitle: "一次处置必须走完整条可信链路", points: ["告警与证据入库", "RAG 与多智能体研判", "策略 / 审批 / 工具执行", "再次验证后才闭环"], accent: "#3d8dff" },
  { kicker: "INNOVATION", title: "三项创新共同约束不确定性", subtitle: "上下文工程 · 受信工具网关 · 受控 ReAct", points: ["tenant-bound 交接与引用", "策略、审批、幂等、恢复", "预算、循环检测与 proposal-only"], accent: "#9b7cff" },
  { kicker: "SAFETY", title: "失败关闭是一项产品能力", subtitle: "未知状态、预算耗尽和审批拒绝都不会继续自动执行", points: ["revision / CAS", "提示与凭据不公开", "非 root · 只读容器", "迁移感知 readiness"], accent: "#22a06b" },
  { kicker: "PRODUCT", title: "六个工作区组成完整产品", subtitle: "总览 · 事件 · 智能体 · 知识库 · 处置 · 报告审计", points: ["跨页运行上下文", "结构化轨迹与人工控制", "公开白名单投影"], accent: "#6dcbf4" },
  { kicker: "EVIDENCE", title: "1029 + 90 项自动化验证", subtitle: "完整后端 1029 passed；前端 90 passed", points: ["脚本合同：53 passed", "容器/供应链：10 passed", "liveness p95：2.499 ms", "RAG 加载 p95：0.114 ms"], accent: "#3d8dff" },
  { kicker: "BOUNDARIES", title: "可信交付必须说清未测边界", subtitle: "离线成功不能替代真实链路验收", points: ["Docker runtime 未测", "GitHub CI 未远端执行", "真实模型规划未测", "真实安全设备未接入"], accent: "#ff9f43" },
  { kicker: "CONCLUSION", title: "让智能体可用的关键，是让每一步都可控", subtitle: "已交付离线产品闭环、确定性边界与可复现证据", points: ["下一步：容器实测 → 受管数据库 → 真实适配器灰度验收", "Q&A"], accent: "#3d8dff" },
];

const SceneView: React.FC<{ scene: Scene; index: number }> = ({ scene, index }) => {
  const frame = useCurrentFrame();
  return (
    <AbsoluteFill className="scene">
      <div className="accent" style={{ backgroundColor: scene.accent, scale: interpolate(frame, [0, 26], [0.2, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp", easing: Easing.bezier(0.16, 1, 0.3, 1) }) }} />
      <main className="content" style={{ opacity: interpolate(frame, [0, 18], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }), translate: interpolate(frame, [0, 24], ["0px 36px", "0px 0px"], { extrapolateLeft: "clamp", extrapolateRight: "clamp", easing: Easing.bezier(0.16, 1, 0.3, 1) }) }}>
        <p className="kicker" style={{ color: scene.accent }}>{scene.kicker}</p>
        <h1>{scene.title}</h1>
        <p className="subtitle">{scene.subtitle}</p>
        <div className="points">
          {scene.points.map((point, i) => (
            <div className="point" key={point} style={{ opacity: interpolate(frame, [20 + i * 9, 36 + i * 9], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }) }}><span style={{ backgroundColor: scene.accent }} />{point}</div>
          ))}
        </div>
      </main>
      <div className="scene-number">{String(index + 1).padStart(2, "0")} / 10</div>
    </AbsoluteFill>
  );
};

export const ShieldChainDemo: React.FC = () => (
  <AbsoluteFill style={{ backgroundColor: "#f7f9fb" }}>
    {scenes.map((scene, index) => (
      <Sequence key={scene.kicker} from={index * sceneFrames} durationInFrames={sceneFrames} premountFor={30}>
        <SceneView scene={scene} index={index} />
      </Sequence>
    ))}
    <CaptionOverlay />
  </AbsoluteFill>
);
