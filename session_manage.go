package main

import (
	"sync"

	"github.com/zonesan/clog"
)

type LogoutQueueManager interface {
	Add(token string) error
	Remove(token string) error
	IsExist(token string) bool
}

type LogoutQueue struct {
	sync.RWMutex
	m map[string]queueInfo
}

type queueInfo struct {
	cleard bool
}

func NewLogoutQueue() LogoutQueueManager {
	clog.Debug("a new logout queue inited...")
	return &LogoutQueue{m: map[string]queueInfo{}}
}

func (lq *LogoutQueue) Add(token string) error {
	clog.Debug("add new token to queue.", token)
	lq.Lock()
	lq.m[token] = queueInfo{}
	lq.Unlock()
	return nil
}
func (lq *LogoutQueue) Remove(token string) error {
	lq.RLock()
	queue, ok := lq.m[token]
	lq.RUnlock()
	if ok {
		queue.cleard = true
		clog.Debug("remove token from queue.(mark as cleard)", token)
		lq.Lock()
		// delete(lq.m, token)
		lq.m[token] = queue
		lq.Unlock()
	}

	return nil
}

func (lq *LogoutQueue) IsExist(token string) bool {
	lq.RLock()
	_, ok := lq.m[token]
	if ok {
		clog.Debug("token exist.", token)
	} else {
		clog.Debug("token not exist.", token)
	}
	lq.RUnlock()
	return ok
}
