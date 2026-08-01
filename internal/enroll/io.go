// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package enroll

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Gneiss-Group/Kessa/internal/chain"
)

// writeChain writes a minted chain to path with 0600 permissions, creating the
// parent directory. The credential is not a public artifact (it is what the
// holder presents), so it is written like the keystore output in publish: private.
func writeChain(path string, ch *chain.Chain) error {
	data, err := ch.Marshal()
	if err != nil {
		return fmt.Errorf("enroll: marshal credential: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("enroll: create credential dir %q: %w", dir, err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("enroll: write credential %q: %w", path, err)
	}
	return nil
}
