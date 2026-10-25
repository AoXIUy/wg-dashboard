package main

import (
	"sync"
	"testing"
	"time"
)

func TestEventBus_PubSub(t *testing.T) {
	bus := NewEventBus()
	defer bus.Close()

	ch1, unsub1 := bus.Subscribe("test_topic", 10)
	defer unsub1()

	ch2, unsub2 := bus.Subscribe("test_topic", 10)
	defer unsub2()

	delivered := bus.Publish("test_topic", "hello world")
	if delivered != 2 {
		t.Fatalf("expected 2 delivered, got %d", delivered)
	}

	select {
	case msg := <-ch1:
		if msg != "hello world" {
			t.Errorf("ch1 expected 'hello world', got '%s'", msg)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("ch1 timeout")
	}

	select {
	case msg := <-ch2:
		if msg != "hello world" {
			t.Errorf("ch2 expected 'hello world', got '%s'", msg)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("ch2 timeout")
	}

	unsub1()
	if count := bus.SubscriberCount("test_topic"); count != 1 {
		t.Errorf("expected 1 subscriber after unsub, got %d", count)
	}
}

func TestMemoryCache_TTLAndHash(t *testing.T) {
	c := NewMemoryCache(1000)

	// String Get/Set
	c.Set("foo", "bar", 50*time.Millisecond)
	val, ok := c.Get("foo")
	if !ok || val != "bar" {
		t.Fatalf("expected 'bar', got '%s'", val)
	}

	time.Sleep(70 * time.Millisecond)
	_, ok = c.Get("foo")
	if ok {
		t.Fatalf("expected 'foo' to be expired")
	}

	// Hash Set/Get/GetAll
	c.HSet("user:1", map[string]interface{}{
		"name": "alice",
		"age":  30,
	}, 100*time.Millisecond)

	name, found := c.HGet("user:1", "name")
	if !found || name != "alice" {
		t.Errorf("expected name 'alice', got '%s'", name)
	}

	all, foundAll := c.HGetAll("user:1")
	if !foundAll || all["age"] != "30" {
		t.Errorf("expected all['age']='30', got '%v'", all)
	}

	// Concurrent writes
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			c.Set("concurrent_key", "val", time.Second)
			c.Get("concurrent_key")
		}(i)
	}
	wg.Wait()
}
