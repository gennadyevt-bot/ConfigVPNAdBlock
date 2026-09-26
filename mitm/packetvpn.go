package mitm

import (
	"configadblock/mitm/internal/packetvpn"
	"fmt"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"strings"
	"sync"
)

var packetVPNMu sync.Mutex
var packetVPN *device.Device

// StartPacketVPN owns fd and connects a packet socket to the WG/AWG engine.
func StartPacketVPN(fd, mtu int64, settings string) error {
	packetVPNMu.Lock()
	defer packetVPNMu.Unlock()
	if packetVPN != nil {
		packetVPN.Close()
		packetVPN = nil
	}
	flowLog("PACKETVPN_START mtu=" + fmt.Sprint(mtu))
	d, err := packetvpn.Start(int(fd), int(mtu), settings, func(fd int) bool {
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
	})
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
}
