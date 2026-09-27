package mitm

import "testing"

func TestPacketVPNHealthNeverExportsKeys(t *testing.T) {
	input := "private_key=secret\npublic_key=peer-secret\npreshared_key=secret\nendpoint=private-host\ntx_bytes=12\nrx_bytes=34\nlast_handshake_time_sec=100\npublic_key=other-secret\ntx_bytes=5\nrx_bytes=6\nlast_handshake_time_sec=200\n"
	want := "peers=2 tx_bytes=17 rx_bytes=40 handshake_unix=200"
	if got := packetVPNHealth(input); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
