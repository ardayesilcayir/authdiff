// Command authdiff finds authorization bugs in REST APIs.
package main

import "fmt"

var version, commit, date = "dev", "none", "unknown"

func main() {
	_ = commit
	_ = date
	fmt.Println("authdiff", version)
}
