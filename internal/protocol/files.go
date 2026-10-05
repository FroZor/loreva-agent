package protocol

import "time"

// File manager message types. Paths are absolute paths as the container
// sees them; only its volumes and mounted folders are reachable.
const (
	FSListType        = "fs.list"
	FSListResultType  = "fs.list.result"
	FSStatType        = "fs.stat"
	FSStatResultType  = "fs.stat.result"
	FSMkdirType       = "fs.mkdir"
	FSRenameType      = "fs.rename"
	FSChmodType       = "fs.chmod"
	FSDeleteType      = "fs.delete"
	FSCopyType        = "fs.copy"
	FSArchiveType     = "fs.archive"
	FSExtractType     = "fs.extract"
	FSCancelType      = "fs.cancel"
	FSProgressType    = "fs.progress"
	FSResultType      = "fs.result"
	FSReadOpenType    = "fs.read.open"
	FSReadOpenedType  = "fs.read.opened"
	FSWriteOpenType   = "fs.write.open"
	FSWriteReadyType  = "fs.write.ready"
	FSWriteResultType = "fs.write.result"
)

// StreamChannelFile carries file content in both directions: downloads
// from the node and uploads from the device.
const StreamChannelFile = 3

// File manager limits.
const (
	// MaxFSOperations bounds the file requests one session runs at once,
	// transfers excluded.
	MaxFSOperations = 4
	// FSVersionAbsent as an expected version requires a new file.
	FSVersionAbsent = "absent"
)

// FSEntry describes a file, folder, or symbolic link.
type FSEntry struct {
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Size       int64     `json:"size"`
	Mode       uint32    `json:"mode"`
	UID        int       `json:"uid"`
	GID        int       `json:"gid"`
	ModifiedAt time.Time `json:"modified_at"`
	LinkTarget string    `json:"link_target,omitempty"`
	Version    string    `json:"version,omitempty"`
	Mount      bool      `json:"mount,omitempty"`
	Virtual    bool      `json:"virtual,omitempty"`
	ReadOnly   bool      `json:"read_only,omitempty"`
}

// FSList asks for one page of a folder, sorted by name.
type FSList struct {
	Type        string `json:"type"`
	RequestID   string `json:"request_id"`
	ContainerID string `json:"container_id"`
	Path        string `json:"path"`
	After       string `json:"after,omitempty"`
}

// FSListResult is one page; More means another page follows After the last
// entry.
type FSListResult struct {
	Type        string    `json:"type"`
	RequestID   string    `json:"request_id"`
	ContainerID string    `json:"container_id"`
	Path        string    `json:"path"`
	Entries     []FSEntry `json:"entries"`
	More        bool      `json:"more"`
}

// FSPathRequest is fs.stat or fs.mkdir.
type FSPathRequest struct {
	Type        string `json:"type"`
	RequestID   string `json:"request_id"`
	ContainerID string `json:"container_id"`
	Path        string `json:"path"`
}

// FSChmod sets the permission bits of a path, 0 to 0777.
type FSChmod struct {
	Type        string `json:"type"`
	RequestID   string `json:"request_id"`
	ContainerID string `json:"container_id"`
	Path        string `json:"path"`
	Mode        uint32 `json:"mode"`
}

// FSStatResult describes one path.
type FSStatResult struct {
	Type        string  `json:"type"`
	RequestID   string  `json:"request_id"`
	ContainerID string  `json:"container_id"`
	Entry       FSEntry `json:"entry"`
}

// FSRename renames or moves a path within one volume.
type FSRename struct {
	Type        string `json:"type"`
	RequestID   string `json:"request_id"`
	ContainerID string `json:"container_id"`
	Path        string `json:"path"`
	To          string `json:"to"`
}

// FSDelete removes paths with everything inside them.
type FSDelete struct {
	Type        string   `json:"type"`
	RequestID   string   `json:"request_id"`
	ContainerID string   `json:"container_id"`
	Paths       []string `json:"paths"`
}

// FSCopy copies paths of one folder into the folder To, possibly in
// another volume.
type FSCopy struct {
	Type        string   `json:"type"`
	RequestID   string   `json:"request_id"`
	ContainerID string   `json:"container_id"`
	Paths       []string `json:"paths"`
	To          string   `json:"to"`
}

// FSArchive packs paths of one folder into the new archive file To.
type FSArchive struct {
	Type        string   `json:"type"`
	RequestID   string   `json:"request_id"`
	ContainerID string   `json:"container_id"`
	Paths       []string `json:"paths"`
	To          string   `json:"to"`
	Format      string   `json:"format"`
}

// FSExtract unpacks the archive at Path into the folder To.
type FSExtract struct {
	Type        string `json:"type"`
	RequestID   string `json:"request_id"`
	ContainerID string `json:"container_id"`
	Path        string `json:"path"`
	To          string `json:"to"`
}

// FSCancel cancels a running fs.delete, fs.copy, fs.archive, or fs.extract.
type FSCancel struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
}

// FSProgress reports a long operation.
type FSProgress struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	Items     int64  `json:"items"`
	Bytes     int64  `json:"bytes"`
}

// FSResult completes fs.mkdir, fs.rename, fs.chmod, fs.delete, fs.copy,
// fs.archive, and fs.extract. Entry is the created or changed object,
// Entries the copies, and Skipped the objects left out.
type FSResult struct {
	Type        string    `json:"type"`
	RequestID   string    `json:"request_id"`
	ContainerID string    `json:"container_id"`
	Entry       *FSEntry  `json:"entry,omitempty"`
	Entries     []FSEntry `json:"entries,omitempty"`
	Items       int64     `json:"items"`
	Bytes       int64     `json:"bytes"`
	Skipped     int64     `json:"skipped"`
}

// FSReadOpen downloads a file from Offset, or a folder as a tar stream, on
// binary channel 3 of StreamID.
type FSReadOpen struct {
	Type        string `json:"type"`
	RequestID   string `json:"request_id"`
	StreamID    uint32 `json:"stream_id"`
	ContainerID string `json:"container_id"`
	Path        string `json:"path"`
	Offset      int64  `json:"offset"`
}

// FSReadOpened confirms a download. Archive means the content is a tar
// stream of a folder.
type FSReadOpened struct {
	Type      string  `json:"type"`
	RequestID string  `json:"request_id"`
	StreamID  uint32  `json:"stream_id"`
	Entry     FSEntry `json:"entry"`
	Offset    int64   `json:"offset"`
	Archive   bool    `json:"archive"`
}

// FSWriteOpen uploads a file of Size bytes whose SHA-256 is SHA256.
// ExpectedVersion "absent" requires a new file; another value requires the
// file to still have that version. Mode applies to a new file.
type FSWriteOpen struct {
	Type            string `json:"type"`
	RequestID       string `json:"request_id"`
	StreamID        uint32 `json:"stream_id"`
	ContainerID     string `json:"container_id"`
	Path            string `json:"path"`
	Size            int64  `json:"size"`
	SHA256          string `json:"sha256"`
	ExpectedVersion string `json:"expected_version,omitempty"`
	Mode            uint32 `json:"mode,omitempty"`
}

// FSWriteReady accepts an upload. The device sends the content from Offset
// on binary channel 3 of StreamID; an interrupted upload of the same file
// and content resumes at the offset already stored.
type FSWriteReady struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	StreamID  uint32 `json:"stream_id"`
	Offset    int64  `json:"offset"`
}

// FSWriteResult completes an upload.
type FSWriteResult struct {
	Type      string  `json:"type"`
	RequestID string  `json:"request_id"`
	StreamID  uint32  `json:"stream_id"`
	Entry     FSEntry `json:"entry"`
}
