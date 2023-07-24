// common.go

package lib

import (
	"bytes"
	"net"
	"sort"
)

// Helper function to sort IP ranges by starting IP.
func sortCIDRs(ipRanges []net.IPNet) {
	sort.SliceStable(ipRanges, func(i, j int) bool {
		return bytes.Compare(ipRanges[i].IP, ipRanges[j].IP) < 0
	})
}
