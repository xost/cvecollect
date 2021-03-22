package main

import (
	"strings"
)

func tabbedLines(lines []string, prefix string, i int) (string, int) {
	str := strings.TrimPrefix(lines[i], prefix) //get part of line after prefix
	str = strings.TrimSpace(str)
	//get get and joit all lines beging with " "
	for i++; i < len(lines) && strings.HasPrefix(lines[i], " "); i++ {
		str += " " + strings.TrimSpace(lines[i])
	}
	i--
	return strings.TrimSpace(str), i
}
