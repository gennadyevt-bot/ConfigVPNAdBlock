package mitm

import (
	"configadblock/mitm/internal/packetvpn"
	"configadblock/mitm/internal/transportdiag"
	"fmt"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"strconv"
	"strings"
	"sync"
)

var packetVPNMu sync.Mutex
var packetVPN *device.Device
var packetTrace *transportdiag.Trace

func packetTraceRef() *transportdiag.Trace {
	packetVPNMu.Lock()
	defer packetVPNMu.Unlock()
	if packetTrace != nil {
		return packetTrace
	}
	return transportdiag.New()
}

// StartPacketVPN owns fd and connects a packet socket to the WG/AWG engine.
func StartPacketVPN(fd, mtu int64, settings string) error {
	packetVPNMu.Lock()
	defer packetVPNMu.Unlock()
	if packetVPN != nil {
		packetVPN.Close()
		packetVPN = nil
	}
	flowLog("PACKETVPN_START mtu=" + fmt.Sprint(mtu))
	packetTrace = transportdiag.New()
	d, err := packetvpn.StartTraced(int(fd), int(mtu), settings, func(fd int) bool {
		protectorMu.RLock()
		p := protector
		protectorMu.RUnlock()
		return p != nil && p.Protect(int64(fd))
	}, func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		flowLog("VPN_ENGINE_ERROR " + msg)
		if strings.Contains(strings.ToLower(msg), "read") {
			flowLog("PACKETVPN_READ_ERR " + msg)
		}
	}, packetTrace)
	if err != nil {
		flowLog("PACKETVPN_ERR " + err.Error())
		return err
	}
	packetVPN = d
	flowLog("PACKETVPN_DEVICE_UP")
	flowLog("VPN_PACKET_ENGINE_UP")
	return nil
}

func StopPacketVPN() {
	packetVPNMu.Lock()
	defer packetVPNMu.Unlock()
	if packetVPN != nil {
		flowLog("PACKETVPN_DEVICE_CLOSED")
		packetVPN.Close()
		packetVPN = nil
	}
	packetTrace = nil
}

// Only export an allowlist of numeric health fields: IpcGet also contains keys.
func packetVPNHealth(settings string) string {
	var peers, tx, rx, handshake int64
	for _, line := range strings.Split(settings, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if key == "public_key" {
			peers++
			continue
		}
		switch key {
		case "tx_bytes", "rx_bytes", "last_handshake_time_sec":
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil || n < 0 {
				continue
			}
			switch key {
			case "tx_bytes":
				tx += n
			case "rx_bytes":
				rx += n
			case "last_handshake_time_sec":
				if n > handshake {
					handshake = n
				}
			}
		}
	}
	return fmt.Sprintf("peers=%d tx_bytes=%d rx_bytes=%d handshake_unix=%d", peers, tx, rx, handshake)
}
func PacketVPNStats() string {
	packetVPNMu.Lock()
	defer packetVPNMu.Unlock()
	if packetVPN == nil {
		return "packetVPN: stopped"
	}
	settings, err := packetVPN.IpcGet()
	if err != nil {
		return "packetVPN: stats unavailable"
	}
	return packetVPNHealth(settings)
}
