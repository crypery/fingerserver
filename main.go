/*
 * Git: https://github.com/crypery
 * Author: https://crypery.com
 * License: GNU AGPL v3 (Affero GPL)
 */
// go1.21.4 windows/amd64
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/wi1dcard/fingerproxy/pkg/metadata"
	"github.com/wi1dcard/fingerproxy/pkg/proxyserver"

	. "data"
	"ip2location"
	"useragent"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	tlsConf  *tls.Config
	ip2db    *ip2location.DB
	ctx      context.Context
	cancel   context.CancelFunc
	tcpStore *TcpStore
	list     = flag.Bool("list", false, "list device")
	dev      = flag.Int("dev", 0, "num device interface")
	ip       = flag.String("ip", "127.0.0.1", "ip server") //
)

// ========================================== Type ========================================== //
type handler func(w http.ResponseWriter, r *http.Request)

type FilteringWriter struct {
	writer    io.Writer
	substring []byte
}

func (fw FilteringWriter) Write(b []byte) (n int, err error) {
	if bytes.Index(b, fw.substring) > -1 {
		// Filter out the line that matches the pattern
		return len(b), nil
	}
	return fw.writer.Write(b)
}

func NewFilteringWriter(writer io.Writer, pattern string) FilteringWriter {
	return FilteringWriter{
		writer:    writer,
		substring: []byte(pattern),
	}
}

// ========================================== TCP Store ========================================== //
type tcpEntry struct {
	html string
	at   time.Time
}

// TcpStore is a bounded, thread-safe store of captured TCP SYN headers,
// keyed by the client endpoint (ip:port). Entries expire after ttl and
// the oldest entry is evicted when the store is full.
type TcpStore struct {
	mu  sync.Mutex
	m   map[string]tcpEntry
	max int
	ttl time.Duration
}

func NewTcpStore(max int, ttl time.Duration) *TcpStore {
	return &TcpStore{
		m:   make(map[string]tcpEntry, max),
		max: max,
		ttl: ttl,
	}
}

func (s *TcpStore) Set(key, html string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.m) >= s.max {
		s.evictOldest()
	}
	s.m[key] = tcpEntry{html: html, at: time.Now()}
}

// Wait blocks until an entry for key appears or timeout elapses.
func (s *TcpStore) Wait(key string, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	for {
		s.mu.Lock()
		e, ok := s.m[key]
		html := ""
		if ok && time.Since(e.at) <= s.ttl {
			html = e.html
		}
		s.mu.Unlock()
		if html != "" {
			return html
		}
		if time.Now().After(deadline) {
			return ""
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Purge removes expired entries.
func (s *TcpStore) Purge() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for key, e := range s.m {
		if now.Sub(e.at) > s.ttl {
			delete(s.m, key)
		}
	}
}

func (s *TcpStore) evictOldest() {
	var oldestKey string
	var oldestAt time.Time
	for key, e := range s.m {
		if oldestKey == "" || e.at.Before(oldestAt) {
			oldestKey, oldestAt = key, e.at
		}
	}
	delete(s.m, oldestKey)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		return "127.0.0.1"
	}
	return host
}

// ========================================== HTML ========================================== //
func GetHtml(w http.ResponseWriter, r *http.Request) {

	defer func() {
		if err := recover(); err != nil {
			pc, fn, line, _ := runtime.Caller(1)
			log.Printf("GetHtml error(%s): %s[%s:%d] %v\n", r.URL.Path, runtime.FuncForPC(pc).Name(), fn, line, err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	}()

	old := r.URL.Path
	if (r.URL.Path == "") || (r.URL.Path == "/") {
		r.URL.Path = "/index.html"
	}
	if r.URL.Path == "/" {
		r.URL.Path = "/index.html"
	}

	file_path := path.Join(("panel/"), path.Clean(r.URL.Path))
	mimetype := mime.TypeByExtension(path.Ext(file_path))
	if r.URL.Path == "/" {
		mimetype = "text/html; charset=utf-8"
	}

	if mimetype != "" {
		w.Header().Set("Content-Type", mimetype)
	} else {
		w.Header().Set("Content-Type", "application/octet-stream; charset=utf-8")
	}

	r.URL.Path = old
	/*-----------------------------------------------------------------------------------------------------------------
	http.ServeFile(w, r, file_path)
	return
	*/
	data, err := Asset(file_path)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	fmt.Fprintf(w, "%s", data)

	return
}

func HtmlOnly() handler {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx") //Apache/nginx
		w.Header().Set("X-Robots-Tag", "noindex")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == "GET" {
			GetHtml(w, r)
			return
		}
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	}
}

// https://roundproxies.com/blog/what-is-tls-fingerprint/
// https://github.com/dreamerlzl/ebpf-ja3
func GetHttps(w http.ResponseWriter, r *http.Request) {
	//var err error
	//var data []byte

	defer func() {
		if err := recover(); err != nil {
			pc, fn, line, _ := runtime.Caller(1)
			log.Printf("GetHttps error(%s): %s[%s:%d] %v\n", r.URL.Path, runtime.FuncForPC(pc).Name(), fn, line, err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	}()
	d, ok := metadata.FromContext(r.Context())
	if !ok {
		http.Error(w, "failed to get context", http.StatusInternalServerError)
		return
	}

	// prepare response
	response := &echoResponse{
		Detail: &detailResponse{
			Metadata:  d,
			UserAgent: r.UserAgent(),
		},
	}

	// calculate and add fingerprints to the response
	if err := response.fingerprintJA3(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := response.fingerprintJA4(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//response.fingerrpintHTTP2()

	//fmt.Fprintf(w, "User-Agent: %s<br/>\n", response.Detail.UserAgent)
	//fmt.Fprintf(w, "TLS ClientHello Record: %x<br/>", response.Detail.Metadata.ClientHelloRecord)
	fmt.Fprintf(w, "JA3 fingerprint: %s<br/>\n", response.JA3)
	fmt.Fprintf(w, "JA4 fingerprint: %s<br/>\n", response.JA4)
	//fmt.Fprintf(w, "HTTP2 fingerprint: %s<br/>\n", response.HTTP2)

	//data = []byte("https")
	//fmt.Fprintf(w, "%s", data)
	return
}

func HttpsOnly() handler {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx") //Apache/nginx
		w.Header().Set("X-Robots-Tag", "noindex")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == "GET" {
			GetHttps(w, r)
			return
		}
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	}
}

func GetLoc(w http.ResponseWriter, r *http.Request) {
	//var err error
	var data []byte

	defer func() {
		if err := recover(); err != nil {
			pc, fn, line, _ := runtime.Caller(1)
			log.Printf("GetLoc error(%s): %s[%s:%d] %v\n", r.URL.Path, runtime.FuncForPC(pc).Name(), fn, line, err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	}()
	ip := clientIP(r)

	it, err := ip2db.Get_all(ip)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	loc := ""
	//loc = loc "<div class=\"row g-5\"><div class=\"col-md-5 col-lg-4 order-md-last\">"
	loc = loc + fmt.Sprintf("IP: %s<br/>\n", ip)
	loc = loc + fmt.Sprintf("Country: %s (%s)<br/>\n", it.Country_long, it.Country_short)
	loc = loc + fmt.Sprintf("Region: %s<br/>\n", it.Region)
	loc = loc + fmt.Sprintf("City: %s<br/>\n", it.City)
	loc = loc + fmt.Sprintf("Latitude: %f<br/>\n", it.Latitude)
	loc = loc + fmt.Sprintf("Longitude: %f<br/>\n", it.Longitude)
	loc = loc + fmt.Sprintf("Isp: %s<br/>\n", it.Isp)
	//loc = loc + "</div><div class=\"col-md-7 col-lg-8\">"
	//javascript:void(0) onclick=\"return false\"
	loc = loc + "<a id=\"getmap\" href=\"javascript:void(0)\">Geolocation on the map</a><br/><div id=\"map\" style=\"display: none;\"></div><script>"
	loc = loc + "map = null;marker = null;currentPosition = [" + fmt.Sprintf("%f", it.Latitude) + ", " + fmt.Sprintf("%f", it.Longitude) + "];"
	//loc = loc + "getMap(currentPosition, 'You are here');"
	loc = loc + "</script>"
	//loc = loc + "</div></div>"
	data = []byte(loc)
	fmt.Fprintf(w, "%s", data)
	return
}

func LocOnly() handler {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx") //Apache/nginx
		w.Header().Set("X-Robots-Tag", "noindex")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == "GET" {
			GetLoc(w, r)
			return
		}
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	}
}

func GetTcp(w http.ResponseWriter, r *http.Request) {
	//var err error
	var data []byte

	defer func() {
		if err := recover(); err != nil {
			pc, fn, line, _ := runtime.Caller(1)
			log.Printf("GetTcp error(%s): %s[%s:%d] %v\n", r.URL.Path, runtime.FuncForPC(pc).Name(), fn, line, err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	}()
	// wait (up to 3s) until the capture goroutine records the SYN of
	// this very connection; the store is keyed by ip:port
	data = []byte(tcpStore.Wait(r.RemoteAddr, 3*time.Second))
	fmt.Fprintf(w, "%s", data)
	return
}

func TcpOnly() handler {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx") //Apache/nginx
		w.Header().Set("X-Robots-Tag", "noindex")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == "GET" {
			GetTcp(w, r)
			return
		}
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	}
}

func setupTLSConfig() {
	tlsConf = &tls.Config{
		NextProtos: []string{"http/1.1"}, //"h2",
	}

	if tlsCert, err := tls.LoadX509KeyPair("localhost.crt", "localhost.key"); err != nil {
		log.Fatal(err)
	} else {
		tlsConf.Certificates = []tls.Certificate{tlsCert}
	}
}

func GetUa(w http.ResponseWriter, r *http.Request) {
	//var err error
	var data []byte

	defer func() {
		if err := recover(); err != nil {
			pc, fn, line, _ := runtime.Caller(1)
			log.Printf("GetUa error(%s): %s[%s:%d] %v\n", r.URL.Path, runtime.FuncForPC(pc).Name(), fn, line, err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	}()

	//https://github.com/mileusna/useragent
	ua := r.UserAgent()
	uu := useragent.Parse(ua)
	ru := fmt.Sprintf("User-agent: %s<br/>\n", ua)
	ru = ru + fmt.Sprintf("Browser: %s<br/>\n", strings.TrimSpace(uu.Name+" "+uu.Version))
	ru = ru + fmt.Sprintf("OS: %s<br/>\n", strings.TrimSpace(uu.OS+" "+uu.OSVersion))
	/*
		dev := ""
		if len(uu.Device) > 0 {
			dev = dev + uu.Device + " "
		}
		if uu.Mobile {
			dev = dev + "Mobile "
		}
		if uu.Tablet {
			dev = dev + "Tablet "
		}
		if uu.Desktop {
			dev = dev + "Desktop "
		}
		if uu.Bot {
			dev = dev + "Bot "
		}
		ru = ru + fmt.Sprintf("Device: %s<br/>\n", strings.TrimSpace(dev))
	*/
	data = []byte(ru)
	fmt.Fprintf(w, "%s", data)
	return
}

func UaOnly() handler {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx") //Apache/nginx
		w.Header().Set("X-Robots-Tag", "noindex")
		if r.Method == "GET" {
			GetUa(w, r)
			return
		}
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	}
}

// ========================================== Main ========================================== //
/*
TLS 1.0 = $0301$
TLS 1.1 = $0302$
TLS 1.2 = $0303$
TLS 1.3 = $0304$
*/
/*
TLS v1.2

TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA8)
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0XC030)
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA9)
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0XC02C)
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0XC02B)
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (0x009E)
TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (0x009F)
TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCAA)

Notes NoWin:
 TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCAA)
Notes Win:
 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256

TLS v1.3:
TLS_AES_256_GCM_SHA384 (0x1302)
TLS_CHACHA20_POLY1305_SHA256 (0x1303)
TLS_AES_128_GCM_SHA256 (0x1301)
*/
/*
1. **DF Flag** (Don't Fragment) - рандомизация 50/50
2. **IP ID** - случайное значение (все пакеты кроме SYN)
3. **Window Size** - диапазон 32768-65535 (только SYN пакеты)
4. **IP Reserved Bit** - рандомизация 50/50
5. **TCP Reserved Bits** - случайные 3 бита
6. **TCP Urgent Pointer** - случайное значение (когда URG=0)
7. **TCP MSS** (Maximum Segment Size) - диапазон 536-1460 с шагом 4 (232 значения)

*/
func captureLoop(ctx context.Context, handle *pcap.Handle) {
	// Set a BPF filter to capture only TCP SYN packets
	filter := "tcp and (tcp[tcpflags] & tcp-syn != 0) and (tcp[tcpflags] & tcp-ack == 0) and (dst host " + *ip + ") and (dst port 443)"
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Println("BPF filter error: ", err.Error())
		return
	}
	log.Println("Capturing only TCP SYN packets...")

	// Create a packet source to read packets from
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-packets:
			if !ok {
				return
			}
			// Process the packet
			ip4Layer := packet.Layer(layers.LayerTypeIPv4)
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer == nil {
				continue
			}
			ip4, _ := ip4Layer.(*layers.IPv4)
			tcp, _ := tcpLayer.(*layers.TCP)
			if ip4 == nil || tcp == nil {
				continue
			}
			ipopt := ""
			for _, val := range ip4.Options {
				ipopt = ipopt + fmt.Sprintf("%d: %X<br/>\n", val.OptionType, val.OptionData)
			}

			tcpopt := ""
			for _, val := range tcp.Options {
				tcpopt = tcpopt + fmt.Sprintf("%s: %X<br/>\n", val.OptionType, val.OptionData)
			}

			ip_dat := fmt.Sprintf("Src: %s:%d<br/>\nDst: %s:%d<br/>\nVersion: %d<br/>\nIHL: %d<br/>\nTOS: %d<br/>\nLength: %d<br/>\nId: %d<br/>\nFlags: %v<br/>\nFragOffset: %d<br/>\nTTL:%d<br/>\nProtocol: %v<br/>\nChecksum: %d<br/>\n%s<br/>\n",
				ip4.SrcIP, tcp.SrcPort, ip4.DstIP, tcp.DstPort, ip4.Version, ip4.IHL, ip4.TOS, ip4.Length, ip4.Id, ip4.Flags, ip4.FragOffset, ip4.TTL, ip4.Protocol, ip4.Checksum, ipopt)

			tcp_dat := fmt.Sprintf("Seq: %d<br/>\nAck: %d<br/>\nDataOffset: %d<br/>\nWindow: %d<br/>\nChecksum: %d<br />\nUrgent: %d<br/>\n%s<br/>\n",
				tcp.Seq, tcp.Ack, tcp.DataOffset, tcp.Window, tcp.Checksum, tcp.Urgent, tcpopt)

			key := net.JoinHostPort(ip4.SrcIP.String(), strconv.Itoa(int(tcp.SrcPort)))
			tcpStore.Set(key, "<div class=\"row g-5\"><div class=\"col-md-5 col-lg-4 order-md-last\">" + ip_dat + "</div><div class=\"col-md-7 col-lg-8\">" + tcp_dat + "</div></div>")
		}
	}
}

func main() {
	flag.Parse()
	ctx, cancel = signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	if *list {

		// Choose an active device (e.g., the first one found)
		if len(devices) == 0 {
			log.Fatal("No network devices found.")
		}
		fmt.Printf("Device count: %d\n", len(devices))
		for index, value := range devices {
			fmt.Printf("%d device: \t%s\t%s\n", index, value.Name, value.Description)
		}
		return
	}
	if *dev < 0 || *dev >= len(devices) {
		log.Fatalf("device index %d out of range [0, %d)", *dev, len(devices))
	}
	device := devices[*dev]
	fmt.Printf("Capturing on device: %s %s\n", device.Name, device.Description)

	// Open the device for capturing
	handle, err := pcap.OpenLive(
		device.Name,
		1024*8,        // Snapshot length (max bytes per packet to capture)
		true,          // Promiscuous mode
		1*time.Second, // Timeout
	)
	if err != nil {
		log.Fatal(err)
	}

	defer handle.Close()
	ip2db, err = ip2location.OpenDB("IP-COUNTRY-REGION-CITY-LATITUDE-LONGITUDE-ISP.BIN") //IP-COUNTRY-REGION-CITY-LATITUDE-LONGITUDE-ISP.BIN
	if err != nil {
		log.Println("Error ip2location: ", err.Error())
		os.Exit(1)
	}
	defer ip2db.Close()

	tcpStore = NewTcpStore(4096, time.Minute)
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				tcpStore.Purge()
			}
		}
	}()

	go captureLoop(ctx, handle)

	go func() {
		setupTLSConfig()
		server := proxyserver.NewServer(ctx, http.HandlerFunc(HttpsOnly()), tlsConf)
		server.HTTPServer.SetKeepAlivesEnabled(false)
		if err := server.ListenAndServe(*ip + ":4443"); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Println("PROXY critical error: ", err.Error())
		}
	}()

	//hashi = hash(CSalt + *Web_Username + *Web_Password)
	errorLogger := log.New(NewFilteringWriter(os.Stderr, "http: TLS handshake error"), "filtered: ", log.LstdFlags)
	http_panel := http.NewServeMux()

	http_panel.HandleFunc("/", HtmlOnly()) //https://getbootstrap.com/docs/5.0/examples/checkout/
	http_panel.HandleFunc("/ua", UaOnly())
	http_panel.HandleFunc("/loc", LocOnly())
	http_panel.HandleFunc("/tcp", TcpOnly())

	server_panel := &http.Server{
		Addr:              *ip + ":443",
		Handler:           http_panel,
		ErrorLog:          errorLogger,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	server_panel.SetKeepAlivesEnabled(false)

	panelErr := make(chan error, 1)
	go func() {
		if err := server_panel.ListenAndServeTLS("localhost.crt", "localhost.key"); err != nil && !errors.Is(err, http.ErrServerClosed) {
			panelErr <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Println("Shutting down...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := server_panel.Shutdown(shutdownCtx); err != nil {
			log.Println("PANEL shutdown error: ", err.Error())
		}
	case err := <-panelErr:
		log.Println("WEB critical error: ", err.Error())
		os.Exit(1)
	}
}
