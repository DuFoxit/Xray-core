package stats

import (
	"sync"

	"net"
)

type userHostMap map[string]bool

type connectionCounter struct {
	*sync.RWMutex
	Counter map[string]userHostMap
}

func GetAddrIP(remoteAddr net.Addr) string {
	switch addr := remoteAddr.(type) {
	case *net.UDPAddr:
		return addr.IP.String()
	case *net.TCPAddr:
		return addr.IP.String()
	}
	return ""
}

func (counter *connectionCounter) AddConnection(user string, host string) {
	if user != "" && host != "" {
		counter.Lock()
		defer counter.Unlock()

		if _, hasUser := counter.Counter[user]; hasUser == false {
			counter.Counter[user] = make(userHostMap)
		}
		counter.Counter[user][host] = true
	}
}

func (counter *connectionCounter) DelConnection(user string, host string) {
	if user != "" && host != "" {
		counter.Lock()
		defer counter.Unlock()

		if hosts, hasUser := counter.Counter[user]; hasUser {
			if _, hasHost := hosts[host]; hasHost {
				delete(hosts, host)
			}
			if len(hosts) == 0 {
				delete(counter.Counter, user)
			}
		}
	}
}

func (counter *connectionCounter) Get(user string) (user_hosts []string) {
	counter.RLock()
	defer counter.RUnlock()

	if hosts, hasUser := counter.Counter[user]; hasUser {
		for host := range hosts {
			user_hosts = append(user_hosts, host)
		}
	}
	return user_hosts
}

var ConnectionCounter *connectionCounter

func init() {
	ConnectionCounter = &connectionCounter{
		RWMutex: &sync.RWMutex{},
		Counter: make(map[string]userHostMap),
	}
}
