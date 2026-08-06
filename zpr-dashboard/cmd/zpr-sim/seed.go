package main

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
)

// ValKey DB
const (
	defaultDBAddr = "127.0.0.1:6379"
	envDBAddr     = "ZPR_DB_ADDR"
)

const (
	forever = 191001270649
	session = 4 * 60 * 60
)

const source = "seeded"

const identityKey = "device.zpr.adapter.cn"

type node struct {
	cn        string
	addr      string
	substrate string
	vss       string
}

type adapter struct {
	cn       string
	addr     string
	via      string // the node it connects through
	services []string
}

var nodes = []node{
	{"node0.zpr.org", "fd5a:5052:90de::1", "10.0.0.1:5000", "10.0.0.1:6000"},
	{"node1.zpr.org", "fd5a:5052:90de::2", "10.0.0.2:5000", "10.0.0.2:6000"},
}

var adapters = []adapter{
	{"gateway.zpr.org", "fd5a:5052:1::80", "fd5a:5052:90de::1",
		[]string{"WebService", "ApiService", "PingService"}},
	{"auth.zpr.org", "fd5a:5052:1::8443", "fd5a:5052:90de::1", []string{"IdentityService"}},
	{"metrics.zpr.org", "fd5a:5052:1::9100", "fd5a:5052:90de::2", []string{"MetricsService"}},
	{"ops.zpr.org", "fd5a:5052:1::7000", "fd5a:5052:90de::2", []string{"AuditService"}},
	{"client.zpr.org", "fd5a:5052:1::1", "fd5a:5052:90de::1", nil},
}

var links = [][2]string{
	{"fd5a:5052:90de::1", "fd5a:5052:90de::2"},
}

type timestamp struct {
	Secs  int64 `json:"secs_since_epoch"`
	Nanos int   `json:"nanos_since_epoch"`
}

type attribute struct {
	Key       string    `json:"key"`
	Value     []string  `json:"value"`
	ExpiresAt timestamp `json:"expires_at"`
	Source    string    `json:"source"`
}

type nodeRecord struct {
	Ctime         timestamp `json:"ctime"`
	ZprAddr       string    `json:"zpr_addr"`
	CN            string    `json:"cn"`
	SubstrateAddr string    `json:"substrate_addr"`
}

func zaddr(addr string) string { return strings.ReplaceAll(addr, ":", "-") }

func edge(a, b string) string {
	ends := []string{zaddr(a), zaddr(b)}
	slices.Sort(ends)

	return strings.Join(ends, "|")
}

func encode(value any) string {
	out, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}

	return string(out)
}

func attr(key string, values []string, expires int64) string {
	return encode(attribute{
		Key:       key,
		Value:     values,
		ExpiresAt: timestamp{Secs: expires},
		Source:    source,
	})
}

func database() (*valkey, error) {
	addr := os.Getenv(envDBAddr)
	if addr == "" {
		addr = defaultDBAddr
	}

	db, err := dial(addr)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the visa service database at %s: %w", addr, err)
	}

	return db, nil
}

func writeActor(db *valkey, cn, addr, role string, services []string, now int64, stamp string) {
	base := "actor:" + zaddr(addr)

	db.cmd("HSET", base, "identity_keys", encode([]string{identityKey}))
	db.cmd("HSET", base, "ctime", stamp)
	db.cmd("HSET", base, "utime", stamp)

	attrs := [][2]string{
		{identityKey, attr(identityKey, []string{cn}, forever)},
		{"zpr.addr", attr("zpr.addr", []string{addr}, forever)},
		{"zpr.authority", attr("zpr.authority", []string{"vs.zpr/seeded"}, forever)},
		{"zpr.role", attr("zpr.role", []string{role}, now+session)},
		{"zpr.vinst", attr("zpr.vinst", []string{"0"}, now+session)},
	}
	if len(services) > 0 {
		attrs = append(attrs, [2]string{"zpr.services", attr("zpr.services", services, now+session)})
	}

	for _, entry := range attrs {
		db.cmd("HSET", base+":attrs", entry[0], entry[1])
	}

	for _, service := range services {
		db.cmd("SADD", base+":services", service)
		db.cmd("HSET", "service:"+service, "zpr_addr", addr)
	}

	set := "adapters"
	if role == "node" {
		set = "nodes"
	}
	db.cmd("SADD", set, addr)
}

func seed() error {
	db, err := database()
	if err != nil {
		return err
	}
	defer db.Close()

	say("seeding the registry with the demo policy's actors and services")

	at := time.Now()
	now := at.Unix()
	stamp := at.UTC().Format("2006-01-02T15:04:05Z")

	for _, n := range nodes {
		writeActor(db, n.cn, n.addr, "node", nil, now, stamp)

		key := "node:" + zaddr(n.addr)
		db.cmd("SET", key, encode(nodeRecord{
			Ctime:         timestamp{Secs: now},
			ZprAddr:       n.addr,
			CN:            n.cn,
			SubstrateAddr: n.substrate,
		}))
		db.cmd("SET", key+":lastseen", stamp)

		// A recorded VSS address is what the API reports as in_sync.
		db.cmd("SET", key+":vss", encode(map[string]string{"vss_addr": n.vss}))

		fmt.Printf("    node    %-18s %-20s vss %s\n", n.cn, n.addr, n.vss)
	}

	for _, a := range adapters {
		writeActor(db, a.cn, a.addr, "adapter", a.services, now, stamp)
		db.cmd("SADD", "node:"+zaddr(a.via)+":connections", a.addr)

		services := strings.Join(a.services, ", ")
		if services == "" {
			services = "no services"
		}
		fmt.Printf("    adapter %-18s %-20s %s\n", a.cn, a.addr, services)
	}

	for _, link := range links {
		db.cmd("SADD", "topology:edges", edge(link[0], link[1]))
		fmt.Printf("    link    %s <-> %s\n", link[0], link[1])
	}

	if err := db.Err(); err != nil {
		return fmt.Errorf("seed: %w", err)
	}

	fmt.Println("    the service did not authenticate these: they are a fake for the dashboard")

	return nil
}

func keysFor(addr string, services []string) []string {
	base := "actor:" + zaddr(addr)

	keys := []string{base, base + ":attrs", base + ":services"}
	for _, service := range services {
		keys = append(keys, "service:"+service)
	}

	return keys
}

func unseed() error {
	db, err := database()
	if err != nil {
		return err
	}
	defer db.Close()

	say("removing the seeded actors and services")

	for _, n := range nodes {
		for _, key := range keysFor(n.addr, nil) {
			db.cmd("DEL", key)
		}

		key := "node:" + zaddr(n.addr)
		for _, suffix := range []string{"", ":lastseen", ":vss", ":connections"} {
			db.cmd("DEL", key+suffix)
		}

		db.cmd("SREM", "nodes", n.addr)
		fmt.Printf("    removed %s\n", n.cn)
	}

	for _, a := range adapters {
		for _, key := range keysFor(a.addr, a.services) {
			db.cmd("DEL", key)
		}

		db.cmd("SREM", "adapters", a.addr)
		fmt.Printf("    removed %s\n", a.cn)
	}

	for _, link := range links {
		db.cmd("SREM", "topology:edges", edge(link[0], link[1]))
	}

	if err := db.Err(); err != nil {
		return fmt.Errorf("unseed: %w", err)
	}

	return nil
}
