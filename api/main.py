#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import struct
import asyncio
import logging
from fastapi import FastAPI, WebSocket, WebSocketDisconnect

# ==========================================
# 环境变量与日志配置
# ==========================================
UUID = os.environ.get('UUID', 'b831381d-6324-4d53-ad4f-8cda48b30811')
DEBUG = os.environ.get('DEBUG', 'false').lower() == 'true'

log_level = logging.DEBUG if DEBUG else logging.INFO
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==========================================
# FastAPI 应用实例 (ASGI 入口)
# ==========================================
app = FastAPI()

class ProxyHandler:
    def __init__(self, uuid: str):
        self.uuid = uuid
        # 移除连字符并转换为 bytes，用于鉴权比对
        self.uuid_bytes = bytes.fromhex(uuid.replace('-', ''))

    async def handle_vless(self, websocket: WebSocket, first_msg: bytes) -> bool:
        try:
            # 1. 基础校验: 检查长度并确认版本号为 0
            if len(first_msg) < 18 or first_msg[0] != 0:
                return False

            # 2. 校验 UUID
            if first_msg[1:17] != self.uuid_bytes:
                if DEBUG:
                    logger.debug("Unauthorized UUID attempt")
                return False

            # 3. 提取目标地址信息
            i = first_msg[17] + 19
            if i + 3 > len(first_msg):
                return False

            port = struct.unpack('!H', first_msg[i:i+2])[0]
            i += 2
            atyp = first_msg[i]
            i += 1

            host = ''
            if atyp == 1:  # IPv4
                if i + 4 > len(first_msg):
                    return False
                host = '.'.join(str(b) for b in first_msg[i:i+4])
                i += 4
            elif atyp == 2:  # Domain
                if i >= len(first_msg):
                    return False
                host_len = first_msg[i]
                i += 1
                if i + host_len > len(first_msg):
                    return False
                host = first_msg[i:i+host_len].decode()
                i += host_len
            elif atyp == 3:  # IPv6
                if i + 16 > len(first_msg):
                    return False
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}'
                               for j in range(i, i+16, 2))
                i += 16
            else:
                return False

            # 4. 协议握手成功，返回 VLESS 响应头 (0x00)
            await websocket.send_bytes(bytes([0, 0]))

            # 5. 建立 TCP 代理桥接
            try:
                # 建立到目标服务器的原生 TCP 连接
                reader, writer = await asyncio.open_connection(host, port)
                
                if DEBUG:
                    logger.debug(f"Successfully connected to {host}:{port}")

                # 如果 first_msg 还有剩余数据 (Payload)，先发送给目标服务器
                if i < len(first_msg):
                    writer.write(first_msg[i:])
                    await writer.drain()

                # 协程 1: 从 WebSocket 持续读取，写入目标 TCP
                async def forward_ws_to_tcp():
                    try:
                        while True:
                            data = await websocket.receive_bytes()
                            writer.write(data)
                            await writer.drain()
                    except Exception:
                        pass
                    finally:
                        writer.close()
                        await writer.wait_closed()

                # 协程 2: 从目标 TCP 持续读取，写入 WebSocket
                async def forward_tcp_to_ws():
                    try:
                        while True:
                            data = await reader.read(4096)
                            if not data:
                                break
                            await websocket.send_bytes(data)
                    except Exception:
                        pass

                # 6. 并发执行双向流转发，维持全双工通信
                await asyncio.gather(
                    forward_ws_to_tcp(),
                    forward_tcp_to_ws()
                )

            except Exception as e:
                if DEBUG:
                    logger.error(f"TCP connection to {host}:{port} failed: {e}")
                return False

            return True

        except Exception as e:
            if DEBUG:
                logger.error(f"VLESS handler error: {e}")
            return False

# 实例化 Proxy 处理器
proxy = ProxyHandler(UUID)

# ==========================================
# HTTP 路由 (用于浏览器访问时的状态提示或伪装)
# ==========================================
@app.get("/")
@app.get("/{path:path}")
async def health_check():
    return {
        "status": "active", 
        "message": "VLESS over WebSocket is running smoothly."
    }
# ==========================================
# WebSocket 路由接管
# ==========================================
@app.websocket("/{path:path}")
async def websocket_endpoint(websocket: WebSocket, path: str):
    await websocket.accept()
    try:
        # 等待客户端发来的首个协议数据包，超时时间设为 5 秒
        first_msg = await asyncio.wait_for(websocket.receive_bytes(), timeout=5.0)
        
        # 拦截并处理合法的 VLESS 首包
        if len(first_msg) > 17 and first_msg[0] == 0:
            await proxy.handle_vless(websocket, first_msg)
            
    except asyncio.TimeoutError:
        if DEBUG:
            logger.debug("WebSocket initial receive timeout")
    except WebSocketDisconnect:
        pass
    except Exception as e:
        if DEBUG:
            logger.error(f"WebSocket endpoint error: {e}")
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
