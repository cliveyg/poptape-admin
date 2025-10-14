package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type CoverBlock struct {
	File      string
	StartLine int
	EndLine   int
	Count     int
}

func parseCoverLine(line string) (*CoverBlock, error) {
	parts := strings.Fields(line)
	if len(parts) < 3 {
		return nil, fmt.Errorf("not enough fields")
	}
	fileAndRange := parts[0]
	count, err := strconv.Atoi(parts[2])
	if err != nil {
		return nil, err
	}
	colon := strings.Index(fileAndRange, ":")
	if colon == -1 {
		return nil, fmt.Errorf("missing colon")
	}
	file := fileAndRange[:colon]
	rng := fileAndRange[colon+1:]
	rngParts := strings.Split(rng, ",")
	if len(rngParts) != 2 {
		return nil, fmt.Errorf("bad range")
	}
	start := strings.Split(rngParts[0], ".")
	end := strings.Split(rngParts[1], ".")
	startLine, err := strconv.Atoi(start[0])
	if err != nil {
		return nil, err
	}
	endLine, err := strconv.Atoi(end[0])
	if err != nil {
		return nil, err
	}
	return &CoverBlock{File: file, StartLine: startLine, EndLine: endLine, Count: count}, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Usage: list_missed_lines.go cover.out")
		os.Exit(1)
	}
	profile := os.Args[1]
	f, err := os.Open(profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to open coverage profile:", err)
		os.Exit(2)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "mode:") {
			continue
		}
		cb, err := parseCoverLine(line)
		if err != nil {
			continue
		}
		if cb.Count == 0 && cb.EndLine > cb.StartLine {
			// Use build.Default.GOPATH/GOROOT to try to find the full path if needed
			// Just print the segment for now
			fmt.Printf("%s:%d-%d\n", cb.File, cb.StartLine, cb.EndLine)
		}
	}
}
