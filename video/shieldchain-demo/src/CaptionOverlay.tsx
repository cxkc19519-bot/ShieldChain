import type { Caption } from "@remotion/captions";
import { AbsoluteFill, Sequence, useVideoConfig } from "remotion";
import captionData from "../public/captions.json";

const captions = captionData as Caption[];

export const CaptionOverlay: React.FC = () => {
  const { fps } = useVideoConfig();
  return (
    <AbsoluteFill style={{ pointerEvents: "none" }}>
      {captions.map((caption, index) => {
        const from = Math.round((caption.startMs / 1000) * fps);
        const durationInFrames = Math.max(1, Math.round(((caption.endMs - caption.startMs) / 1000) * fps));
        return (
          <Sequence key={`${caption.startMs}-${index}`} from={from} durationInFrames={durationInFrames} layout="none">
            <div className="caption-wrap"><div className="caption">{caption.text}</div></div>
          </Sequence>
        );
      })}
    </AbsoluteFill>
  );
};
