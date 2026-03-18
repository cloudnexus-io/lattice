// Lattice Security - Go/Rust Collector Agent
//
// Collector agent that processes eBPF events and enriches them with
// Kubernetes metadata.

package collector

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// Event types
const (
	EventSocketConnect   = 1
	EventSecurityConnect = 2
	EventSocketState     = 3
	EventDNSQuery        = 4
	EventDNSResponse     = 5
	EventFileOpen        = 6
	EventSensitivePath   = 7
	EventBaselineDrift   = 8
	EventProcessExec     = 9
)

// Severity levels
const (
	SeverityInfo     = 0
	SeverityLow      = 1
	SeverityMedium   = 2
	SeverityHigh     = 3
	SeverityCritical = 4
)

// SecurityEvent represents a security event from eBPF
type SecurityEvent struct {
	EventID      string                 `json:"event_id"`
	Timestamp    time.Time              `json:"timestamp"`
	EventType    string                 `json:"event_type"`
	Severity     string                 `json:"severity"`
	SrcIP        string                 `json:"src_ip"`
	DstIP        string                 `json:"dst_ip"`
	DstPort      uint16                 `json:"dst_port"`
	Protocol     string                 `json:"protocol"`
	PID          uint32                 `json:"pid"`
	TGID         uint32                 `json:"tgid"`
	Comm         string                 `json:"comm"`
	Namespace    string                 `json:"namespace"`
	PodName      string                 `json:"pod_name"`
	ContainerID  string                 `json:"container_id"`
	ContainerImg string                 `json:"container_image"`
	Path         string                 `json:"path,omitempty"`
	Details      map[string]interface{} `json:"details,omitempty"`
	IsDrift      bool                   `json:"is_baseline_violation"`
}

// RawEvent is the binary format from eBPF
type RawEvent struct {
	Timestamp   uint64
	EventType   uint32
	PID         uint32
	TGID        uint32
	Saddr       uint32
	Daddr       uint32
	Dport       uint16
	Family      uint8
	Protocol    uint8
	Comm        [16]byte
	ContainerID [64]byte
	Severity    uint8
	Path        [256]byte
}

// K8sMetadata caches Kubernetes pod information
type K8sMetadata struct {
	PodName      string
	Namespace    string
	ContainerID  string
	ContainerImg string
	NodeName     string
}

// Collector handles eBPF event collection and K8s enrichment
type Collector struct {
	// eBPF resources
	objs          *SecurityBPFObjects
	ringbufReader *ringbuf.Reader

	// Kubernetes client
	k8sClient   *kubernetes.Clientset
	podInformer cache.SharedIndexInformer

	// Metadata cache
	metadataCache sync.Map // containerID -> K8sMetadata
	pidCache      sync.Map // PID -> K8sMetadata

	// Baseline store
	baselineStore *BaselineStore

	// Event sink
	eventSink EventSink

	// Configuration
	config *Config

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Config holds collector configuration
type Config struct {
	NodeName        string
	BackendURL      string
	LearningMode    bool
	BaselineVersion uint32
	EventBufferSize int
}

// SecurityBPFObjects contains the loaded eBPF programs
type SecurityBPFObjects struct {
	SocketTrace *ebpf.Program `ebpf:"handle_tcp_v4_connect"`
	DNSMonitor  *ebpf.Program `ebpf:"handle_dns_query"`
	FileMonitor *ebpf.Program `ebpf:"handle_file_open"`
	Events      *ebpf.Map     `ebpf:"events"`
}

// EventSink is the interface for sending events
type EventSink interface {
	SendEvent(event *SecurityEvent) error
}

// NewCollector creates a new security collector
func NewCollector(cfg *Config) (*Collector, error) {
	ctx, cancel := context.WithCancel(context.Background())

	c := &Collector{
		config: cfg,
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize Kubernetes client
	if err := c.initK8sClient(); err != nil {
		log.Printf("Warning: Failed to init K8s client: %v", err)
	}

	// Initialize baseline store
	c.baselineStore = NewBaselineStore()

	return c, nil
}

// initK8sClient initializes the Kubernetes client
func (c *Collector) initK8sClient() error {
	// Try in-cluster config first
	config, err := rest.InClusterConfig()
	if err != nil {
		// Fall back to local kubeconfig
		config, err = clientcmd.BuildConfigFromFlags("", "")
		if err != nil {
			return fmt.Errorf("failed to get kubeconfig: %w", err)
		}
	}

	c.k8sClient = kubernetes.NewForConfigOrDie(config)

	// Start pod informer for metadata enrichment
	c.podInformer = cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return c.k8sClient.CoreV1().Pods("").List(c.ctx, options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return c.k8sClient.CoreV1().Pods("").Watch(c.ctx, options)
			},
		},
		&v1.Pod{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.onPodAdd,
			UpdateFunc: c.onPodUpdate,
			DeleteFunc: c.onPodDelete,
		},
	)

	go c.podInformer.Run(c.ctx.Done())

	return nil
}

// Start begins collecting security events
func (c *Collector) Start() error {
	// Load eBPF programs
	spec, err := ebpf.LoadLoadSecuritySpecFromDefaults()
	if err != nil {
		return fmt.Errorf("failed to load eBPF spec: %w", err)
	}

	if err := spec.LoadAndAssign(&c.objs, nil); err != nil {
		return fmt.Errorf("failed to load eBPF objects: %w", err)
	}

	// Open ring buffer for events
	eventsMap, ok := c.objs.Events.(*ebpf.Map)
	if !ok {
		return fmt.Errorf("events map is not a ringbuf")
	}

	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return fmt.Errorf("failed to open ring buffer: %w", err)
	}
	c.ringbufReader = rd

	// Attach tracepoints
	if err := c.attachTracepoints(); err != nil {
		return fmt.Errorf("failed to attach tracepoints: %w", err)
	}

	// Start event processing loop
	c.wg.Add(1)
	go c.processEvents()

	log.Printf("Security collector started on node %s", c.config.NodeName)
	return nil
}

// attachTracepoints attaches eBPF programs to kernel tracepoints
func (c *Collector) attachTracepoints() error {
	// TCP connect tracepoint
	tp, err := link.Tracepoint("tcp", "tcp_v4_connect", c.objs.SocketTrace, nil)
	if err != nil {
		return fmt.Errorf("attach tcp_v4_connect: %w", err)
	}
	c.wg.Add(1)
	go func() {
		defer tp.Close()
		<-c.ctx.Done()
		c.wg.Done()
	}()

	return nil
}

// processEvents reads events from the ring buffer
func (c *Collector) processEvents() {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			record, err := c.ringbufReader.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("Ring buffer read error: %v", err)
				continue
			}

			c.handleEvent(record.RawSample)
		}
	}
}

// handleEvent processes a raw eBPF event
func (c *Collector) handleEvent(data []byte) {
	if len(data) < 16 {
		return
	}

	var raw RawEvent
	if err := binary.Read(json.RawMessage(data), binary.LittleEndian, &raw); err != nil {
		log.Printf("Failed to parse event: %v", err)
		return
	}

	// Convert to SecurityEvent
	event := c.enrichEvent(&raw)

	// Check baseline for drift detection
	if c.config.LearningMode {
		c.baselineStore.RecordAccess(event)
	} else {
		drift := c.baselineStore.CheckDrift(event)
		if drift != nil {
			event.IsDrift = true
			event.Severity = "HIGH"
			event.Details = map[string]interface{}{
				"drift_type":    drift.Type,
				"drift_details": drift.Details,
			}
		}
	}

	// Classify severity
	event.Severity = c.classifySeverity(event)

	// Send to backend
	if err := c.eventSink.SendEvent(event); err != nil {
		log.Printf("Failed to send event: %v", err)
	}
}

// enrichEvent adds Kubernetes metadata to an event
func (c *Collector) enrichEvent(raw *RawEvent) *SecurityEvent {
	event := &SecurityEvent{
		EventID:     fmt.Sprintf("%s-%d", c.config.NodeName, raw.Timestamp),
		Timestamp:   time.Unix(0, int64(raw.Timestamp)),
		EventType:   eventTypeToString(raw.EventType),
		PID:         raw.PID,
		TGID:        raw.TGID,
		Comm:        cstringToString(raw.Comm[:]),
		SrcIP:       intToIP(raw.Saddr).String(),
		DstIP:       intToIP(raw.Daddr).String(),
		DstPort:     raw.Dport,
		Protocol:    protocolToString(raw.Protocol),
		ContainerID: cstringToString(raw.ContainerID[:]),
		Path:        cstringToString(raw.Path[:]),
	}

	// Try to get K8s metadata from cache
	if meta, ok := c.metadataCache.Load(event.ContainerID); ok {
		m := meta.(*K8sMetadata)
		event.Namespace = m.Namespace
		event.PodName = m.PodName
		event.ContainerImg = m.ContainerImg
	}

	// Try to get metadata from PID
	if meta, ok := c.pidCache.Load(raw.PID); ok {
		m := meta.(*K8sMetadata)
		if event.Namespace == "" {
			event.Namespace = m.Namespace
			event.PodName = m.PodName
		}
	}

	return event
}

// classifySeverity assigns severity based on event characteristics
func (c *Collector) classifySeverity(event *SecurityEvent) string {
	switch event.EventType {
	case "SOCKET_CONNECT", "DNS_QUERY":
		// Check for suspicious destinations
		if isKnownMaliciousIP(event.DstIP) {
			return "CRITICAL"
		}
		if event.DstIP == "169.254.169.254" {
			return "HIGH"
		}
		return "LOW"

	case "SENSITIVE_PATH_ACCESS":
		if strings.Contains(event.Path, "shadow") ||
			strings.Contains(event.Path, "admin.conf") ||
			strings.Contains(event.Path, "/run/secrets/") {
			return "CRITICAL"
		}
		return "HIGH"

	case "BASELINE_DRIFT":
		return "HIGH"

	default:
		return "INFO"
	}
}

// Pod event handlers
func (c *Collector) onPodAdd(obj interface{}) {
	pod := obj.(*v1.Pod)
	c.updatePodCache(pod)
}

func (c *Collector) onPodUpdate(old, new interface{}) {
	pod := new.(*v1.Pod)
	c.updatePodCache(pod)
}

func (c *Collector) onPodDelete(obj interface{}) {
	pod := obj.(*v1.Pod)
	for _, container := range pod.Status.ContainerStatuses {
		c.metadataCache.Delete(container.ContainerID)
	}
}

func (c *Collector) updatePodCache(pod *v1.Pod) {
	for _, container := range pod.Status.ContainerStatuses {
		meta := &K8sMetadata{
			PodName:      pod.Name,
			Namespace:    pod.Namespace,
			ContainerID:  container.ContainerID,
			ContainerImg: container.Image,
			NodeName:     pod.Spec.NodeName,
		}
		c.metadataCache.Store(container.ContainerID, meta)
	}
}

// BaselineStore manages security baselines
type BaselineStore struct {
	mu        sync.RWMutex
	baselines map[string]*Baseline // keyed by container image hash
}

type Baseline struct {
	Version         uint32
	AllowedPaths    map[string]bool
	AllowedSyscalls map[string]bool
	LastUpdated     time.Time
}

type Drift struct {
	Type    string
	Details string
}

func NewBaselineStore() *BaselineStore {
	return &BaselineStore{
		baselines: make(map[string]*Baseline),
	}
}

func (s *BaselineStore) RecordAccess(event *SecurityEvent) {
	// Learning mode - record allowed access patterns
}

func (s *BaselineStore) CheckDrift(event *SecurityEvent) *Drift {
	// Detection mode - check against baseline
	return nil
}

// Helper functions
func cstringToString(c [64]byte) string {
	n := 0
	for i, b := range c {
		if b == 0 {
			n = i
			break
		}
	}
	return string(c[:n])
}

func intToIP(ip uint32) net.IP {
	return net.IP{
		byte(ip >> 24),
		byte(ip >> 16),
		byte(ip >> 8),
		byte(ip),
	}
}

func eventTypeToString(t uint32) string {
	switch t {
	case EventSocketConnect:
		return "SOCKET_CONNECT"
	case EventSecurityConnect:
		return "SECURITY_CONNECT"
	case EventDNSQuery:
		return "DNS_QUERY"
	case EventFileOpen:
		return "FILE_OPEN"
	case EventSensitivePath:
		return "SENSITIVE_PATH_ACCESS"
	default:
		return "UNKNOWN"
	}
}

func protocolToString(p uint8) string {
	switch p {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("PROTO-%d", p)
	}
}

func isKnownMaliciousIP(ip string) bool {
	// Would integrate with threat intelligence feed
	return false
}

// Stop gracefully shuts down the collector
func (c *Collector) Stop() {
	c.cancel()
	c.ringbufReader.Close()
	c.wg.Wait()
}
