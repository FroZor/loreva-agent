package state

// CheckOwner is a no-op on Windows, where the state directory is protected
// by an explicit ACL instead of Unix ownership.
func (s *Store) CheckOwner() error { return nil }
