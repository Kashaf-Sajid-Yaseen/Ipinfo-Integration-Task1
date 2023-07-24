// cmd_tool_lower.go
package lib

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	// Update with your actual project's packag
	"github.com/spf13/pflag"
)

// CmdToolLowerFlags are flags expected by CmdToolLower.
type CmdToolLowerFlags struct {
	Help  bool
	Quiet bool
}

// Init initializes the common flags available to CmdToolLower with sensible defaults.
//
// pflag.Parse() must be called to actually use the final flag values.
func (f *CmdToolLowerFlags) Init() {
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

// CmdToolLower is the common core logic for calculating the network IP address (lower address of a network).
func CmdToolLower(
	f CmdToolLowerFlags,
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

	// Parses a list of IPs and CIDRs.
	parseIPsAndCIDRs := func(rows []string) []net.IPNet {
		parsedIPsAndCIDRs := make([]net.IPNet, 0)
		for _, str := range rows {
			_, ipNet, err := net.ParseCIDR(str)
			if err == nil {
				parsedIPsAndCIDRs = append(parsedIPsAndCIDRs, *ipNet)
				continue
			}

			ip := net.ParseIP(str)
			if ip != nil {
				// Convert IP to CIDR.
				ones, bits := ip.DefaultMask().Size()
				ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(ones, bits)}
				parsedIPsAndCIDRs = append(parsedIPsAndCIDRs, *ipNet)
				continue
			}

			if !f.Quiet {
				fmt.Printf("Invalid input: %s\n", str)
			}
		}

		return parsedIPsAndCIDRs
	}

	// Input parser.
	parseInput := func(rows []string) []net.IPNet {
		return parseIPsAndCIDRs(rows)
	}

	// Input scanner.
	scanrdr := func(r io.Reader) []string {
		rows := make([]string, 0)

		buf := bufio.NewReader(r)
		for {
			d, err := buf.ReadString('\n')
			if err == io.EOF {
				if len(d) == 0 {
					break
				}
			} else if err != nil {
				if !f.Quiet {
					fmt.Printf("Scan error: %v\n", err)
				}
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

	// Vars to contain IPs and CIDRs from all input sources.
	parsedIPsAndCIDRs := make([]net.IPNet, 0)

	// Collect IPs and CIDRs from stdin.
	if isStdin {
		rows := scanrdr(os.Stdin)
		parsedIPsAndCIDRs = parseInput(rows)
	}

	// Collect IPs and CIDRs from all args.
	for _, arg := range args {
		file, err := os.Open(arg)
		if err != nil {
			parsedIPsAndCIDRs = append(parsedIPsAndCIDRs, parseInput([]string{arg})...)
			continue
		}

		rows := scanrdr(file)
		file.Close()
		parsedIPsAndCIDRs = append(parsedIPsAndCIDRs, parseInput(rows)...)
	}

	// Calculate the network IP address and print it.
	for _, cidrStr := range args {
		ipRange, err := IPRangeStrFromCIDR(cidrStr)
		if err != nil {
			if !f.Quiet {
				fmt.Printf("Error parsing CIDR: %v\n", err)
			}
			continue
		}

		fmt.Println(ipRange.Start) // Print the start IP of the IP range
	}

	return nil
}
