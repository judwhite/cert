package openssl

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

func Run(stdin []byte, args ...string) ([]byte, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	fmt.Printf("openssl %s\n", strings.Join(args, " "))

	cmd := exec.Command("openssl", args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		combined := stdout.Bytes()
		combined = append(combined, stderr.Bytes()...)
		return combined, err
	}

	return stdout.Bytes(), nil
}
