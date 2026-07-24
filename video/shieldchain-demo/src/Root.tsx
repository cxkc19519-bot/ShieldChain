import "./index.css";
import { Composition } from "remotion";
import { ShieldChainDemo } from "./Composition";

export const RemotionRoot: React.FC = () => {
  return (
    <Composition
      id="ShieldChainDemo"
      component={ShieldChainDemo}
      durationInFrames={5400}
      fps={30}
      width={1920}
      height={1080}
      defaultProps={{}}
    />
  );
};
