package lib

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/spf13/pflag"
)

// CmdToolUpperFlags are flags expected by CmdToolUpper.
type CmdToolUpperFlags struct {
	Help  bool
	Quiet bool
}

// Init initializes the common flags available to CmdToolUpper with sensible defaults.
//
// pflag.Parse() must be called to actually use the final flag values.
func (f *CmdToolUpperFlags) Init() {
	pflag.BoolVarP(
		&f.Help,
		"help", "h", false,
		"show help.",
	)
	pflag.BoolVarP(
		&f.Quiet,
		"quiet", "q", false,
		"quiet mode; suppress additional output.",
	)
}

// CmdToolUpper is the common core logic for calculating the upper IP address (end address of a network).
func CmdToolUpper(
	f CmdToolUpperFlags,
	args []string,
	printHelp func(),
) error {
	if f.Help {
		printHelp()
		return nil
	}

	// require args.
	stat, _ := os.Stdin.Stat()
	isStdin := (stat.Mode() & os.ModeCharDevice) == 0
	if len(args) == 0 && !isStdin {
		printHelp()
		return nil
	}

	// Parses a list of CIDRs and IPs.

	parseCIDRsAndIPs := func(items []string) ([]net.IP, error) {
		parsedIPs := make([]net.IP, 0)
		for _, item := range items {
			// Check if the input is a CIDR.
			if strings.ContainsRune(item, '/') {
				ipRange, err := IPRangeStrFromCIDR(item) // Use IPRangeStrFromCIDR from ip_range_str.go to get IPRangeStr for CIDR.
				if err != nil {
					return nil, err
				}
				// The last IP in the range will be the broadcast IP for the CIDR.
				endIP := net.ParseIP(ipRange.End)
				parsedIPs = append(parsedIPs, endIP)
			} else {
				// Check if the input is a single IP.
				ip := net.ParseIP(item)
				if ip == nil {
					return nil, fmt.Errorf("invalid input: %q", item)
				}
				parsedIPs = append(parsedIPs, ip)
			}
		}
		return parsedIPs, nil
	}
	// Vars to contain IPs from all input sources.
	parsedIPs := make([]net.IP, 0)

	// Collect IPs from stdin.
	if isStdin {
		rows := scanrdr(os.Stdin)
		ips, err := parseCIDRsAndIPs(rows)
		if err != nil {
			if !f.Quiet {
				fmt.Println(err)
			}
			return nil
		}
		parsedIPs = append(parsedIPs, ips...)
	}

	// Collect IPs from all args.
	for _, arg := range args {
		file, err := os.Open(arg)
		if err != nil {
			ips, err := parseCIDRsAndIPs([]string{arg})
			if err != nil {
				if !f.Quiet {
					fmt.Println(err)
				}
			}
			parsedIPs = append(parsedIPs, ips...)
			continue
		}

		rows := scanrdr(file)
		file.Close()
		ips, err := parseCIDRsAndIPs(rows)
		if err != nil {
			if !f.Quiet {
				fmt.Println(err)
			}
		}
		parsedIPs = append(parsedIPs, ips...)
	}

	// Print the broadcast IPs.
	for _, ip := range parsedIPs {
		fmt.Println(ip.String())
	}

	return nil
}

func scanrdr(r io.Reader) []string {
	rows := make([]string, 0)

	buf := bufio.NewReader(r)
	for {
		d, err := buf.ReadString('\n')
		if err == io.EOF {
			if len(d) == 0 {
				break
			}
		} else if err != nil {
			return rows
		}

		sepIdx := strings.IndexAny(d, "\n")
		if sepIdx == -1 {
			// only possible if EOF & input doesn't end with newline.
			sepIdx = len(d)
		}

		rowStr := d[:sepIdx]
		rows = append(rows, rowStr)
	}

	return rows
}
