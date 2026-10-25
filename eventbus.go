package main

import (
	"sync"
)

// EventBus 是进程内高性能并发安全的发布/订阅消息总线，完全替代 Redis Pub/Sub
type EventBus struct {
	mu          sync.RWMutex
	subscribers map[string]map[chan string]struct{}
	closed      bool
}

var globalEventBus *EventBus

func initEventBus() {
	globalEventBus = NewEventBus()
}

// NewEventBus 创建消息总线
func NewEventBus() *EventBus {
	return &EventBus{
		subscribers: make(map[string]map[chan string]struct{}),
	}
}

// Subscribe 订阅指定 topic 的消息。返回消息通道以及取消订阅的注销函数
func (eb *EventBus) Subscribe(topic string, bufferSize int) (<-chan string, func()) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	if bufferSize <= 0 {
		bufferSize = 100
	}

	ch := make(chan string, bufferSize)
	if _, ok := eb.subscribers[topic]; !ok {
		eb.subscribers[topic] = make(map[chan string]struct{})
	}
	eb.subscribers[topic][ch] = struct{}{}

	unsubscribe := func() {
		eb.mu.Lock()
		defer eb.mu.Unlock()

		if subs, ok := eb.subscribers[topic]; ok {
			if _, exists := subs[ch]; exists {
				delete(subs, ch)
				close(ch)
				if len(subs) == 0 {
					delete(eb.subscribers, topic)
				}
			}
		}
	}

	return ch, unsubscribe
}

// Publish 向指定 topic 广播消息，采用非阻塞投递，防止慢消费者堵塞总线
func (eb *EventBus) Publish(topic string, payload string) int {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	subs, ok := eb.subscribers[topic]
	if !ok || len(subs) == 0 {
		return 0
	}

	delivered := 0
	for ch := range subs {
		select {
		case ch <- payload:
			delivered++
		default:
			// 慢消费者通道满时丢弃最新帧，保证系统低延迟
		}
	}
	return delivered
}

// SubscriberCount 返回指定 topic 的当前活跃订阅者数量
func (eb *EventBus) SubscriberCount(topic string) int {
	eb.mu.RLock()
	defer eb.mu.RUnlock()
	return len(eb.subscribers[topic])
}

// Close 关闭所有订阅通道
func (eb *EventBus) Close() {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	if eb.closed {
		return
	}
	eb.closed = true

	for _, subs := range eb.subscribers {
		for ch := range subs {
			close(ch)
		}
	}
	eb.subscribers = make(map[string]map[chan string]struct{})
}
