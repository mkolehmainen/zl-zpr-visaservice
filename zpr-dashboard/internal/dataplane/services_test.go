package dataplane

import "testing"

// svcAddr is the actor address the Targets fixtures answer on.
const svcAddr = "fd5a:5052:90de::30"

// visaFor builds a visa with the given direction, protocol and ports.
func visaFor(direction, proto, src, dst string, srcPort, dstPort int) VisaDescriptor {
	return VisaDescriptor{
		Direction:  direction,
		Proto:      proto,
		SourceAddr: &src,
		DestAddr:   &dst,
		SourcePort: &srcPort,
		DestPort:   &dstPort,
	}
}

// TestServiceTargets covers the address, direction, protocol and port rules
// that decide whether a visa was granted for a service's endpoints.
func TestServiceTargets(t *testing.T) {
	peer := "fd5a:5052:90de::40"

	cases := []struct {
		name      string
		endpoints string
		dock      string
		visa      VisaDescriptor
		want      bool
	}{
		{
			name:      "forward tcp hit",
			endpoints: "TCP/443",
			visa:      visaFor("forward", "TCP", peer, svcAddr, 0, 443),
			want:      true,
		},
		{
			name:      "reverse tcp hit, service on the source side",
			endpoints: "TCP/443",
			visa:      visaFor("reverse", "TCP", svcAddr, peer, 443, 0),
			want:      true,
		},
		{
			name:      "right address, wrong port",
			endpoints: "TCP/443",
			visa:      visaFor("forward", "TCP", peer, svcAddr, 0, 9000),
			want:      false,
		},
		{
			name:      "right port, wrong protocol",
			endpoints: "TCP/443",
			visa:      visaFor("forward", "UDP", peer, svcAddr, 0, 443),
			want:      false,
		},
		{
			name:      "port inside a declared range",
			endpoints: "TCP/8000-8080",
			visa:      visaFor("forward", "TCP", peer, svcAddr, 0, 8042),
			want:      true,
		},
		{
			name:      "port outside a declared range",
			endpoints: "TCP/8000-8080",
			visa:      visaFor("forward", "TCP", peer, svcAddr, 0, 8081),
			want:      false,
		},
		{
			name:      "endpoint with no port matches any port",
			endpoints: "TCP/",
			visa:      visaFor("forward", "TCP", peer, svcAddr, 0, 31337),
			want:      true,
		},
		{
			name:      "icmp type matches",
			endpoints: "IPV6_ICMP/128",
			visa:      visaFor("forward", "ICMP", peer, svcAddr, 128, 0),
			want:      true,
		},
		{
			name:      "icmp type mismatch",
			endpoints: "IPV6_ICMP/128",
			visa:      visaFor("forward", "ICMP", peer, svcAddr, 129, 0),
			want:      false,
		},
		{
			name:      "icmp range matches its low value",
			endpoints: "IPV6_ICMP/128-129",
			visa:      visaFor("forward", "ICMP", peer, svcAddr, 128, 0),
			want:      true,
		},
		{
			name:      "icmp range matches its high value",
			endpoints: "IPV6_ICMP/128-129",
			visa:      visaFor("reverse", "ICMP", svcAddr, peer, 129, 0),
			want:      true,
		},
		{
			name:      "icmp range excludes an intermediate value",
			endpoints: "IPV6_ICMP/128-135",
			visa:      visaFor("forward", "ICMP", peer, svcAddr, 130, 0),
			want:      false,
		},
		{
			name:      "PROTO_58 spelling normalizes to the visa's ICMP",
			endpoints: "PROTO_58/128",
			visa:      visaFor("forward", "ICMP", peer, svcAddr, 128, 0),
			want:      true,
		},
		{
			name:      "endpoint ICMP is IPv4 and misses an IPv6 visa",
			endpoints: "ICMP/128",
			visa:      visaFor("forward", "ICMP", peer, svcAddr, 128, 0),
			want:      false,
		},
		{
			name:      "endpoint PROTO_1 is IPv4 and misses an IPv6 visa",
			endpoints: "PROTO_1/128",
			visa:      visaFor("forward", "ICMP", peer, svcAddr, 128, 0),
			want:      false,
		},
		{
			name:      "PROTO_6 normalizes to TCP",
			endpoints: "PROTO_6/443",
			visa:      visaFor("forward", "TCP", peer, svcAddr, 0, 443),
			want:      true,
		},
		{
			name:      "PROTO_17 normalizes to UDP",
			endpoints: "PROTO_17/53",
			visa:      visaFor("forward", "UDP", peer, svcAddr, 0, 53),
			want:      true,
		},
		{
			name:      "malformed port fails closed",
			endpoints: "TCP/https",
			visa:      visaFor("forward", "TCP", peer, svcAddr, 0, 443),
			want:      false,
		},
		{
			name:      "reversed range fails closed",
			endpoints: "TCP/8080-8000",
			visa:      visaFor("forward", "TCP", peer, svcAddr, 0, 8042),
			want:      false,
		},
		{
			name:      "dock address hit",
			endpoints: "TCP/443",
			dock:      "fd5a:5052:90de::99",
			visa:      visaFor("forward", "TCP", peer, "fd5a:5052:90de::99", 0, 443),
			want:      true,
		},
		{
			name:      "visa with no five-tuple",
			endpoints: "TCP/443",
			visa:      VisaDescriptor{Direction: "forward", Proto: "N/A"},
			want:      false,
		},
		{
			name:      "service with no declared endpoints",
			endpoints: "",
			visa:      visaFor("forward", "TCP", peer, svcAddr, 0, 443),
			want:      false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc := ServiceDescriptor{ZprAddress: svcAddr, DockZprAddress: c.dock, Endpoints: c.endpoints}
			if got := svc.Targets(c.visa); got != c.want {
				t.Errorf("Targets() = %v, want %v", got, c.want)
			}
		})
	}
}
