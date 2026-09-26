package mitm

import (
	"configadblock/mitm/internal/packetvpn"
	"fmt"
	"github.com/amnezia-vpn/amneziawg-go/device"
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
	d, err := packetvpn.Start(int(fd), int(mtu), settings, func(fd int) bool {
		protectorMu.RLock()
		p := protector
		protectorMu.RUnlock()
		return p != nil && p.Protect(int64(fd))
	}, func(format string, args ...any) { flowLog("VPN_ENGINE_ERROR " + fmt.Sprintf(format, args...)) })
	if err != nil {
		return err
	}
	packetVPN = d
	flowLog("VPN_PACKET_ENGINE_UP")
	return nil
}

func StopPacketVPN() {
	packetVPNMu.Lock()
	defer packetVPNMu.Unlock()
	if packetVPN != nil {
		packetVPN.Close()
		packetVPN = nil
	}
}
