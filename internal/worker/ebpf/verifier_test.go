//go:build linux

package ebpf

import (
	"os"
	"testing"

	cebpf "github.com/cilium/ebpf"
)

func TestTLSUprobeCollectionLoads(t *testing.T) {
	if os.Getenv("K8SHARK_TEST_BPF_LOAD") != "1" {
		t.Skip("set K8SHARK_TEST_BPF_LOAD=1 for a privileged kernel load")
	}
	spec, err := loadTls()
	if err != nil {
		t.Fatal(err)
	}
	for name := range spec.Programs {
		if name == "kprobe_tcp_sendmsg" || name == "kprobe_tcp_recvmsg" {
			delete(spec.Programs, name)
		}
	}
	coll, err := cebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	coll.Close()
}
