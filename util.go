package main

import (
	"strings"
)

func tabbedLines(lines []string, prefix string, i int) (string, int) {
	str := strings.TrimPrefix(lines[i], prefix)
	str = strings.TrimSpace(str)
	for i++; i < len(lines) && strings.HasPrefix(lines[i], " "); i++ {
		str += " " + strings.TrimSpace(lines[i])
	}
	i--
	return strings.TrimSpace(str), i
}
