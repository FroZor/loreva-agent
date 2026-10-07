package state

// Claim is a no-op on Windows, where the state directory is protected by an
// explicit ACL instead of Unix ownership.
func (s *Store) Claim() error { return nil }
