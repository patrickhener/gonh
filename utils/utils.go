package utils

import "strings"

// SevAtoi will return a numeric severity value when providing a string one.
func SevAtoi(sev string) int {
	switch strings.ToLower(sev) {
	case "cri":
		return 4
	case "hig":
		return 3
	case "med":
		return 2
	case "low":
		return 1
	case "non":
		return 0
	default:
		return 0
	}
}

// SevSItoa will return a severity from non-cri when providing a number (as string).
func SevSItoa(sev string) string {
	switch sev {
	case "4":
		return "Cri"
	case "3":
		return "Hig"
	case "2":
		return "Med"
	case "1":
		return "Low"
	case "0":
		return "Non"
	default:
		return "Non"
	}
}
