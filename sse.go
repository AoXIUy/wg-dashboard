package main

import (
	"context"
	"io"
	"time"

	"github.com/gin-gonic/gin"
)

// ================= SSE Broker =================

// startSSEBroker 管理 SSE 客户端的注册/注销与消息广播
func startSSEBroker(ctx context.Context) {
	defer logger.Println("SSE Broker 已停止")
	for {
		select {
		case <-ctx.Done():
			return
		case s := <-sseBroker.NewClients:
			sseBroker.mu.Lock()
			sseBroker.Clients[s] = true
			sseBroker.mu.Unlock()
			logger.Printf("新 SSE 客户端连接，当前连接数: %d", len(sseBroker.Clients))

		case s := <-sseBroker.ClosedClients:
			sseBroker.mu.Lock()
			delete(sseBroker.Clients, s)
			clientCount := len(sseBroker.Clients)
			sseBroker.mu.Unlock()
			close(s)
			logger.Printf("SSE 客户端断开，当前连接数: %d", clientCount)

		case msg := <-sseBroker.Message:
			sseBroker.mu.RLock()
			clientCount := len(sseBroker.Clients)
			sseBroker.mu.RUnlock()

			if clientCount == 0 {
				continue
			}

			// 限流检查
			lastBroadcast := sseBroker.lastBroadcast.Load().(time.Time)
			if time.Since(lastBroadcast) < sseBroker.rateLimit {
				continue
			}
			sseBroker.lastBroadcast.Store(time.Now())

			sseBroker.mu.RLock()
			for s := range sseBroker.Clients {
				select {
				case s <- msg:
				default:
					// 客户端阻塞，异步移除
					go func(client chan string) {
						sseBroker.mu.Lock()
						delete(sseBroker.Clients, client)
						sseBroker.mu.Unlock()
						close(client)
					}(s)
				}
			}
			sseBroker.mu.RUnlock()
		}
	}
}

// startRedisBroadcastListener 订阅 Redis Pub/Sub 频道，将消息转发给本地 SSE Broker
func startRedisBroadcastListener(ctx context.Context) {
	logger.Println("Redis Pub/Sub 监听器已启动")
	defer logger.Println("Redis Pub/Sub 监听器已停止")

	pubsub := rdb.Subscribe(ctx, "wg:channel:broadcast")
	defer pubsub.Close()

	ch := pubsub.Channel()

	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			select {
			case sseBroker.Message <- msg.Payload:
			default:
			}
		}
	}
}

// streamHandler 处理 SSE 长连接请求
func streamHandler(c *gin.Context) {
	clientChan := make(chan string, 10)
	sseBroker.NewClients <- clientChan

	defer func() {
		sseBroker.ClosedClients <- clientChan
	}()

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("Transfer-Encoding", "chunked")
	c.Writer.Header().Set("X-Accel-Buffering", "no") // 禁用 Nginx 缓冲

	c.Stream(func(w io.Writer) bool {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		select {
		case msg, ok := <-clientChan:
			if !ok {
				return false
			}
			c.SSEvent("message", msg)
			return true
		case <-ticker.C:
			// 发送心跳注释保持连接
			c.Writer.Write([]byte(": keepalive\n\n"))
			return true
		case <-c.Request.Context().Done():
			return false
		}
	})
}
