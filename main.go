package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/Devatoria/go-nsenter"
	"github.com/prometheus/procfs"
)

const (
	pathTCPTab  = "/proc/net/tcp"
	pathTCP6Tab = "/proc/net/tcp6"
	pathUDPTab  = "/proc/net/udp"
	pathUDP6Tab = "/proc/net/udp6"
	ipv4StrLen  = 8
	ipv6StrLen  = 32
)

// Socket states
const (
	Established SkState = 0x01
	SynSent             = 0x02
	SynRecv             = 0x03
	FinWait1            = 0x04
	FinWait2            = 0x05
	TimeWait            = 0x06
	Close               = 0x07
	CloseWait           = 0x08
	LastAck             = 0x09
	Listen              = 0x0a
	Closing             = 0x0b
)

var skStates = [...]string{
	"UNKNOWN",
	"ESTABLISHED",
	"SYN_SENT",
	"SYN_RECV",
	"FIN_WAIT1",
	"FIN_WAIT2",
	"TIME_WAIT",
	"", // CLOSE
	"CLOSE_WAIT",
	"LAST_ACK",
	"LISTEN",
	"CLOSING",
}

// SockAddr represents an ip:port pair
type SockAddr struct {
	IP   net.IP
	Port uint16
}

func (s *SockAddr) String() string {
	return fmt.Sprintf("%v:%d", s.IP, s.Port)
}

// SockTabEntry type represents each line of the /proc/net/[tcp|udp]
type SockTabEntry struct {
	ino        string
	LocalAddr  *SockAddr
	RemoteAddr *SockAddr
	State      SkState
	UID        uint32
	Process    *Process
}

// SkState type represents socket connection state
type SkState uint8

func (s SkState) String() string {
	return skStates[s]
}

func parseIPv4(s string) (net.IP, error) {
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return nil, err
	}
	ip := make(net.IP, net.IPv4len)
	binary.LittleEndian.PutUint32(ip, uint32(v))
	return ip, nil
}

func parseIPv6(s string) (net.IP, error) {
	ip := make(net.IP, net.IPv6len)
	const grpLen = 4
	i, j := 0, 4
	for len(s) != 0 {
		grp := s[0:8]
		u, err := strconv.ParseUint(grp, 16, 32)
		binary.LittleEndian.PutUint32(ip[i:j], uint32(u))
		if err != nil {
			return nil, err
		}
		i, j = i+grpLen, j+grpLen
		s = s[8:]
	}
	return ip, nil
}

func parseAddr(s string) (*SockAddr, error) {
	fields := strings.Split(s, ":")
	if len(fields) < 2 {
		return nil, fmt.Errorf("netstat: not enough fields: %v", s)
	}
	var ip net.IP
	var err error
	switch len(fields[0]) {
	case ipv4StrLen:
		ip, err = parseIPv4(fields[0])
	case ipv6StrLen:
		ip, err = parseIPv6(fields[0])
	default:
		err = fmt.Errorf("netstat: bad formatted string: %v", fields[0])
	}
	if err != nil {
		return nil, err
	}
	v, err := strconv.ParseUint(fields[1], 16, 16)
	if err != nil {
		return nil, err
	}
	return &SockAddr{IP: ip, Port: uint16(v)}, nil
}

func ParseAddrHex(net_addr_hex string) net.IP {
	a, _ := hex.DecodeString(net_addr_hex)
	ipv4 := net.IPv4(a[3], a[2], a[1], a[0])
	return ipv4
}

func ParsePortHex(net_port_hex string) int {
	net_port, err := strconv.ParseInt(net_port_hex, 16, 32)
	if err != nil {
		log.Fatal(err)
	}
	return int(net_port)
}

func ParseStatusHex(net_status_hex string) string {
	switch net_status_hex {
	case "01":
		return "TCP_ESTABLISHED"
	case "02":
		return "TCP_SYN_SENT"
	case "03":
		return "TCP_SYN_RECV"
	case "04":
		return "TCP_FIN_WAIT1"
	case "05":
		return "TCP_FIN_WAIT2"
	case "06":
		return "TCP_TIME_WAIT"
	case "07":
		return "TCP_CLOSE"
	case "08":
		return "TCP_CLOSE_WAIT"
	case "09":
		return "TCP_LAST_ACK"
	case "0A":
		return "TCP_LISTEN"
	case "0B":
		return "TCP_CLOSING"
	case "0C":
		return "TCP_NEW_SYN_RECV"
	default:
		return "UNKNOWN"
	}
}

type TcpConn struct {
	ParentHostname string
	// Hostname
	Hostname string
	// The process name
	Name string
	// The process id
	Pid int
	// The local address of the connection.
	LocalAddr net.IP
	// The local port
	LocalPort int
	// The remote address of the connection.
	RemoteAddr net.IP
	RemoteName string
	// The remote port
	RemotePort int
	// Status
	Status string
	// Protocol
	Protocol string
	// UTS hostname
	UTSHostname string
}

type Process struct {
	ParentHostname  string
	Pid             int
	Ppid            int
	Name            string
	TcpConnections  []TcpConn       `json:"connections"`
	NumberOfThreads int             `json:"number_of_threads"`
	Threads         []ProcessThread `json:"threads"`
	// UTS hostname
	UTSHostname string
}

type ProcessThread struct {
	Pid            int             `json:"pid"`
	Ppid           int             `json:"ppid"`
	Name           string          `json:"name"`
	Threads        []ProcessThread `json:"threads"`
	TcpConnections []TcpConn       `json:"connections"`
	// UTS hostname
	UTSHostname    string
	ParentHostname string
}

// AcceptFn is used to filter socket entries. The value returned indicates
// whether the element is to be appended to the socket list.
type AcceptFn func(*SockTabEntry) bool

func parseSocktab(r io.Reader, accept AcceptFn) ([]SockTabEntry, error) {
	br := bufio.NewScanner(r)
	tab := make([]SockTabEntry, 0, 4)

	// Discard title
	br.Scan()

	for br.Scan() {
		var e SockTabEntry
		line := br.Text()
		// Skip comments
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 12 {
			return nil, fmt.Errorf("netstat: not enough fields: %v, %v", len(fields), fields)
		}
		addr, err := parseAddr(fields[1])
		if err != nil {
			return nil, err
		}
		e.LocalAddr = addr
		addr, err = parseAddr(fields[2])
		if err != nil {
			return nil, err
		}
		e.RemoteAddr = addr
		u, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil {
			return nil, err
		}
		e.State = SkState(u)
		u, err = strconv.ParseUint(fields[7], 10, 32)
		if err != nil {
			return nil, err
		}
		e.UID = uint32(u)
		e.ino = fields[9]
		if accept(&e) {
			tab = append(tab, e)
		}
	}
	return tab, br.Err()
}

// doNetstat - collect information about network port status
func doNetstat(path string, fn AcceptFn) ([]SockTabEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	tabs, err := parseSocktab(f, fn)
	f.Close()
	if err != nil {
		return nil, err
	}

	return tabs, nil
}

func GetConnectionList(entries []SockTabEntry, hostname string, pid int, processName string, parentHostname string) []TcpConn {
	connections := make([]TcpConn, 0)
	for _, entry := range entries {
		conn := TcpConn{
			Name:           strings.Replace(strings.TrimSpace(processName), "\n", "", -1),
			Pid:            pid,
			LocalAddr:      entry.LocalAddr.IP,
			LocalPort:      int(entry.LocalAddr.Port),
			RemoteAddr:     entry.RemoteAddr.IP,
			RemotePort:     int(entry.RemoteAddr.Port),
			Status:         entry.State.String(),
			Hostname:       strings.Replace(strings.TrimSpace(hostname), "\n", "", -1),
			UTSHostname:    strings.Replace(strings.TrimSpace(hostname), "\n", "", -1),
			ParentHostname: strings.Replace(strings.TrimSpace(parentHostname), "\n", "", -1),
		}
		connections = append(connections, conn)
	}
	return connections
}

// TCPSocks returns a slice of active TCP sockets containing only those
// elements that satisfy the accept function
func osTCPSocks(accept AcceptFn, pid int) ([]SockTabEntry, error) {
	path := fmt.Sprintf("/proc/%d/net/tcp", pid)
	return doNetstat(path, accept)
}

// TCP6Socks returns a slice of active TCP IPv4 sockets containing only those
// elements that satisfy the accept function
func osTCP6Socks(accept AcceptFn, pid int) ([]SockTabEntry, error) {
	path := fmt.Sprintf("/proc/%d/net/tcp6", pid)
	return doNetstat(path, accept)
}

// UDPSocks returns a slice of active UDP sockets containing only those
// elements that satisfy the accept function
func osUDPSocks(accept AcceptFn) ([]SockTabEntry, error) {
	return doNetstat(pathUDPTab, accept)
}

// UDP6Socks returns a slice of active UDP IPv6 sockets containing only those
// elements that satisfy the accept function
func osUDP6Socks(accept AcceptFn) ([]SockTabEntry, error) {
	return doNetstat(pathUDP6Tab, accept)
}

// TCPSocks returns a slice of active TCP sockets containing only those
// elements that satisfy the accept function
func TCPSocks(accept AcceptFn, pid int) ([]SockTabEntry, error) {
	return osTCPSocks(accept, pid)
}

// TCP6Socks returns a slice of active TCP IPv4 sockets containing only those
// elements that satisfy the accept function
func TCP6Socks(accept AcceptFn, pid int) ([]SockTabEntry, error) {
	return osTCP6Socks(accept, pid)
}

// UDP6Socks returns a slice of active UDP IPv6 sockets containing only those
// elements that satisfy the accept function
func UDP6Socks(accept AcceptFn) ([]SockTabEntry, error) {
	return osUDP6Socks(accept)
}

func GetTcpConnections(pid string, hostname string, processName string, parentHostname string) []TcpConn {
	var fn AcceptFn
	fn = func(*SockTabEntry) bool { return true }
	pid_, _ := strconv.Atoi(pid)
	tabsTcp, _ := TCPSocks(fn, pid_)
	pid_, _ = strconv.Atoi(pid)
	tabsTcp6, _ := TCP6Socks(fn, pid_)

	tcp6conn := GetConnectionList(tabsTcp, hostname, pid_, processName, parentHostname)
	tcp4conn := GetConnectionList(tabsTcp6, hostname, pid_, processName, parentHostname)

	return append(tcp6conn, tcp4conn...)
}

func main() {
	// Get hostname
	parentHostname, _ := os.Hostname()

	if len(os.Args) > 1 {
		pid := os.Args[1]
		if pid != "" {
			// Get hostname
			hostname, err := os.Hostname()
			if err != nil {
				log.Fatal(err)
			}
			hostname = strings.TrimSpace(hostname)
			pid = strings.TrimSpace(pid)
			parentHostname = strings.TrimSpace(parentHostname)
			connections := GetTcpConnections(pid, hostname, "", parentHostname)
			// Write json to stdout
			b, err := json.Marshal(connections)
			if err != nil {
				fmt.Println(err)
				return
			}
			fmt.Println(string(b))
			os.Exit(1)
		}
	}

	processes := make([]Process, 0)

	if len(os.Args) == 1 {
		// Walk through the entire process tree.
		procs, err := procfs.AllProcs()
		if err != nil {
			log.Fatalf("could not get process list: %s", err)
		}
		for _, p := range procs {
			stat, err := p.Stat()
			if err != nil {
				log.Printf("could not get process stat for %d: %s", p.PID, err)
				continue
			}
			// Get the pid
			pid_ := strconv.Itoa(stat.PID)

			config := &nsenter.Config{
				UTS:    true,
				Target: stat.PID, // Enter into PID namespace
			}
			stdout, _, err := config.Execute("/bin/cat", "/proc/sys/kernel/hostname")
			if err != nil {
			        stdout = ""
			}
			// Get the netstat
			connections := GetTcpConnections(pid_, stdout, stat.Comm, parentHostname)
			process := Process{Pid: stat.PID, Ppid: stat.PPID, Name: stat.Comm, TcpConnections: connections, UTSHostname: stdout, ParentHostname: parentHostname}
			// Process all threads
			threads, err := procfs.AllThreads(p.PID)
			if err != nil {
				log.Printf("could not get threads for %d: %s", p.PID, err)
				continue
			}
			process.NumberOfThreads = len(threads)
			process.Threads = make([]ProcessThread, 0, len(threads))
			if err != nil {
				log.Printf("could not get thread list for %d: %s", p.PID, err)
				continue
			}
			for _, t := range threads {
				threadStat, err := t.Stat()
				if err != nil {
					log.Printf("could not get thread stat for %d: %s", t.PID, err)
					continue
				}
				tPIDstr := strconv.Itoa(t.PID)
				connections := GetTcpConnections(tPIDstr, stdout, threadStat.Comm, parentHostname)
				// Get the pid
				thread := ProcessThread{Pid: threadStat.PID, Ppid: threadStat.PPID, Name: threadStat.Comm, TcpConnections: connections, ParentHostname: parentHostname}
				process.Threads = append(process.Threads, thread)
			}
			processes = append(processes, process)
		}

		allConnections := make([]TcpConn, 0)
		for _, p := range processes {
			allConnections = append(allConnections, p.TcpConnections...)
			for _, t := range p.Threads {
				allConnections = append(allConnections, t.TcpConnections...)
			}
		}
		// Write json to stdout
		b, err := json.Marshal(allConnections)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(string(b))

	}

}
