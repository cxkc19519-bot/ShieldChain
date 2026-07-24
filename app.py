import subprocess
import sys
import time
import os
import signal
from pathlib import Path

def main():
    print("🚀 SAGA 一键启动脚本启动中...")
    
    # 1. 检查并生成 PKI (如果没有的话)
    pki_dir = Path("tests/fixtures/pki")
    if not pki_dir.exists() or not list(pki_dir.glob("*.pem")):
        print("🛠️ 正在生成测试环境 PKI 证书...")
        subprocess.run([sys.executable, "scripts/create_test_ca.py", "--out", str(pki_dir)], check=True)
        print("✅ PKI 证书生成完毕。")
    else:
        print("✅ 发现现有 PKI 证书，跳过生成。")

    processes = []

    try:
        # 2. 启动 Provider (8000)
        print("🌐 正在启动 SAGA Provider (Port 8000)...")
        p_provider = subprocess.Popen([sys.executable, "scripts/run_provider.py", "--port", "8000"])
        processes.append(p_provider)
        time.sleep(2) # 等待 provider 启动

        # 3. 启动 Agent Alice (8001)
        print("🤖 正在启动 Agent Alice (Port 8001)...")
        p_alice = subprocess.Popen([sys.executable, "scripts/run_agent.py", "--port", "8001", "--owner", "alice", "--name", "agent-a"])
        processes.append(p_alice)

        # 4. 启动 Agent Bob (8002)
        print("🤖 正在启动 Agent Bob (Port 8002)...")
        p_bob = subprocess.Popen([sys.executable, "scripts/run_agent.py", "--port", "8002", "--owner", "bob", "--name", "agent-b"])
        processes.append(p_bob)
        
        # 5. 启动 React 前端控制台 (Vite)
        frontend_dir = Path("frontend")
        if frontend_dir.exists() and (frontend_dir / "package.json").exists():
            print("🖥️  正在启动 React 可视化控制台...")
            npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
            p_frontend = subprocess.Popen([npm_cmd, "run", "dev"], cwd=str(frontend_dir))
            processes.append(p_frontend)
        
        print("\n" + "="*50)
        print("🎉 SAGA 全生态启动成功！")
        print("📍 Provider API:    https://localhost:8000")
        print("📍 Agent Alice:     https://localhost:8001")
        print("📍 Agent Bob:       https://localhost:8002")
        print("📊 React Dashboard: http://localhost:5173 (通常)")
        print("="*50 + "\n")
        
        print("按下 Ctrl+C 安全退出所有服务...")
        
        # 阻塞主进程
        for p in processes:
            p.wait()

    except KeyboardInterrupt:
        print("\n🛑 收到退出信号，正在关闭所有 SAGA 服务...")
    finally:
        # 优雅地杀死所有子进程
        for p in processes:
            try:
                if p.poll() is None: # 进程还在运行
                    if os.name == 'nt':
                        # Windows 需要发 CTRL_C_EVENT 或者 terminate
                        p.terminate()
                    else:
                        p.send_signal(signal.SIGTERM)
            except Exception:
                pass
        print("👋 拜拜！")

if __name__ == "__main__":
    main()
