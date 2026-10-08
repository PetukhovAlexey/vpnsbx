// drvcheck — диагностика драйвера NDISRD: версия, адаптеры и (sniff) формат
// кадров на адаптере в режиме прослушивания (пакеты не задерживаются).
package main

import (
	"fmt"
	"os"
	"time"

	A "github.com/wiresock/ndisapi-go"
	"golang.org/x/sys/windows"
)

func main() {
	api, err := A.NewNdisApi()
	if err != nil {
		fmt.Println("open:", err)
		return
	}
	defer api.Close()
	v, err := api.GetVersion()
	fmt.Printf("loaded=%v version=%#x err=%v\n", api.IsDriverLoaded(), v, err)
	l, err := api.GetTcpipBoundAdaptersInfo()
	if err != nil {
		fmt.Println("adapters:", err)
		return
	}
	sniff := ""
	if len(os.Args) == 3 && os.Args[1] == "sniff" {
		sniff = os.Args[2]
	}
	for i := 0; i < int(l.AdapterCount); i++ {
		name := api.ConvertWindows2000AdapterName(string(l.AdapterNameList[i][:]))
		fmt.Printf("%d: %s medium=%d mtu=%d\n", i, name, l.AdapterMediumList[i], l.MTU[i])
		if name == sniff {
			sniffAdapter(api, l.AdapterHandle[i])
		}
	}
}

// sniffAdapter 3 с слушает адаптер и печатает длину и первые 14 байт кадров.
func sniffAdapter(api *A.NdisApi, h A.Handle) {
	ev, _ := windows.CreateEvent(nil, 1, 0, nil)
	defer windows.CloseHandle(ev)
	api.SetPacketEvent(h, ev)
	api.SetAdapterMode(&A.AdapterMode{AdapterHandle: h, Flags: A.MSTCP_FLAG_SENT_LISTEN | A.MSTCP_FLAG_RECV_LISTEN})
	defer func() {
		api.SetAdapterMode(&A.AdapterMode{AdapterHandle: h})
		api.SetPacketEvent(h, 0)
	}()
	bufs := make([]A.IntermediateBuffer, 64)
	ptrs := make([]*A.IntermediateBuffer, len(bufs))
	for i := range bufs {
		ptrs[i] = &bufs[i]
	}
	shown := 0
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end) && shown < 6; {
		windows.WaitForSingleObject(ev, 200)
		windows.ResetEvent(ev)
		var n uint32
		if !api.ReadPacketsUnsorted(ptrs, uint32(len(ptrs)), &n) {
			continue
		}
		for i := 0; i < int(n) && shown < 6; i++ {
			b := ptrs[i]
			fmt.Printf("   flags=%d len=%d first14=% x\n", b.DeviceFlags, b.Length, b.Buffer[:14])
			shown++
		}
	}
}
