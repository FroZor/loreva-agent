package direct_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"path/filepath"
	"testing"

	"github.com/FroZor/loreva-agent/internal/client"
	"github.com/FroZor/loreva-agent/internal/containerfiles"
	"github.com/FroZor/loreva-agent/internal/containerio"
	"github.com/FroZor/loreva-agent/internal/fileops"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

// fakeFiles runs the real file helper in-process over pipes, with one
// temporary folder as the container's only mount.
type fakeFiles struct {
	client *fileops.Client
	mount  string
}

func newFakeFiles(t *testing.T) *fakeFiles {
	t.Helper()

	mount := t.TempDir()
	helperIn, agentOut := io.Pipe()
	agentIn, helperOut := io.Pipe()
	go func() {
		_ = fileops.Serve(helperIn, helperOut)
		helperOut.Close()
	}()
	t.Cleanup(func() { agentOut.Close() })

	files := &fakeFiles{client: fileops.NewClient(agentIn, agentOut), mount: mount}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	if err := files.client.Init(ctx, []fileops.Mount{{Path: mount}}); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	return files
}

func (f *fakeFiles) Start(_ context.Context, containerID string, request fileops.Request) (containerfiles.Call, error) {
	if containerID != testContainerID {
		return nil, containerio.ErrNotFound
	}

	return f.client.Start(request)
}

const (
	fileRequestID   = "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65"
	fileStreamID    = 5
	fileUploadBytes = protocol.StreamWindowBytes + 700*1024
)

func TestDeviceFileManager(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	node := startNode(t)
	session, err := client.Connect(ctx, pairDevice(ctx, t, node))
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer session.Close()
	mount := node.files.mount

	send(ctx, t, session, protocol.FSPathRequest{Type: protocol.FSMkdirType, RequestID: fileRequestID, ContainerID: testContainerID, Path: mount + "/world"})
	var created protocol.FSResult
	expect(ctx, t, session, protocol.FSResultType, &created)
	if created.Entry == nil || created.Entry.Type != "directory" {
		t.Fatalf("fs.mkdir result = %+v", created)
	}

	content := bytes.Repeat([]byte("0123456789abcdef"), fileUploadBytes/16)
	written := upload(ctx, t, session, mount+"/world/region.mca", content)
	if written.Entry.Size != int64(len(content)) || written.Entry.Version == "" {
		t.Fatalf("fs.write.result entry = %+v", written.Entry)
	}

	send(ctx, t, session, protocol.FSList{Type: protocol.FSListType, RequestID: fileRequestID, ContainerID: testContainerID, Path: mount + "/world"})
	var listed protocol.FSListResult
	expect(ctx, t, session, protocol.FSListResultType, &listed)
	if len(listed.Entries) != 1 || listed.Entries[0].Name != "region.mca" || listed.More {
		t.Fatalf("fs.list result = %+v", listed)
	}

	opened, downloaded := download(ctx, t, session, mount+"/world/region.mca")
	if !bytes.Equal(downloaded, content) || opened.Entry.Version != written.Entry.Version {
		t.Fatalf("downloaded %d bytes with version %s, want %d with %s", len(downloaded), opened.Entry.Version, len(content), written.Entry.Version)
	}

	send(ctx, t, session, protocol.FSArchive{
		Type: protocol.FSArchiveType, RequestID: fileRequestID, ContainerID: testContainerID,
		Paths: []string{mount + "/world"}, To: mount + "/world.zip", Format: "zip",
	})
	progressed := false
	for done := false; !done; {
		data, err := session.Read(ctx)
		if err != nil {
			t.Fatalf("read fs.archive reply: %v", err)
		}
		switch messageType, _ := protocol.MessageType(data); messageType {
		case protocol.FSProgressType:
			progressed = true
		case protocol.FSResultType:
			done = true
		default:
			acknowledge(ctx, t, session, messageType, data, protocol.FSResultType)
		}
	}
	if !progressed {
		t.Fatal("fs.archive reported no progress")
	}
	reader, err := zip.OpenReader(filepath.Join(mount, "world.zip"))
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	reader.Close()

	send(ctx, t, session, protocol.FSPathRequest{Type: protocol.FSStatType, RequestID: fileRequestID, ContainerID: testContainerID, Path: "/etc/passwd"})
	var refused protocol.Error
	expect(ctx, t, session, protocol.ErrorType, &refused)
	if refused.Code != "outside_mounts" {
		t.Fatalf("fs.stat outside the mounts = %+v", refused)
	}
}

// upload sends content with fs.write.open, honouring the node's credit.
func upload(ctx context.Context, t *testing.T, session *client.Session, path string, content []byte) protocol.FSWriteResult {
	t.Helper()

	sum := sha256.Sum256(content)
	send(ctx, t, session, protocol.FSWriteOpen{
		Type: protocol.FSWriteOpenType, RequestID: fileRequestID, StreamID: fileStreamID, ContainerID: testContainerID,
		Path: path, Size: int64(len(content)), SHA256: hex.EncodeToString(sum[:]), ExpectedVersion: protocol.FSVersionAbsent,
	})
	var ready protocol.FSWriteReady
	expect(ctx, t, session, protocol.FSWriteReadyType, &ready)

	window := int64(protocol.StreamWindowBytes)
	sent := ready.Offset
	for {
		for sent < int64(len(content)) && window > 0 {
			size := min(int64(protocol.MaxStreamChunkBytes), int64(len(content))-sent, window)
			if err := session.WriteStream(ctx, protocol.StreamChannelFile, fileStreamID, content[sent:sent+size]); err != nil {
				t.Fatalf("send upload data: %v", err)
			}
			sent += size
			window -= size
		}

		data, err := session.Read(ctx)
		if err != nil {
			t.Fatalf("read upload reply: %v", err)
		}
		messageType, _ := protocol.MessageType(data)
		switch messageType {
		case protocol.StreamCreditType:
			var credit protocol.StreamCredit
			if err := protocol.DecodeStrict(data, &credit); err != nil || credit.StreamID != fileStreamID {
				t.Fatalf("stream.credit = %s", data)
			}
			window += credit.Bytes
		case protocol.FSWriteResultType:
			var result protocol.FSWriteResult
			if err := protocol.DecodeStrict(data, &result); err != nil {
				t.Fatalf("fs.write.result = %s", data)
			}
			if sent != int64(len(content)) {
				t.Fatalf("result arrived after %d of %d bytes", sent, len(content))
			}
			return result
		default:
			acknowledge(ctx, t, session, messageType, data, protocol.FSWriteResultType)
		}
	}
}

// download reads a file with fs.read.open, returning credit as it goes.
func download(ctx context.Context, t *testing.T, session *client.Session, path string) (protocol.FSReadOpened, []byte) {
	t.Helper()

	send(ctx, t, session, protocol.FSReadOpen{
		Type: protocol.FSReadOpenType, RequestID: fileRequestID, StreamID: fileStreamID, ContainerID: testContainerID, Path: path,
	})

	var (
		opened  protocol.FSReadOpened
		content bytes.Buffer
	)
	for {
		isBinary, data, err := session.ReadFrame(ctx)
		if err != nil {
			t.Fatalf("read download: %v", err)
		}
		if isBinary {
			if data[0] != protocol.StreamChannelFile || binary.BigEndian.Uint32(data[1:5]) != fileStreamID {
				t.Fatalf("bad stream frame header % x", data[:5])
			}
			content.Write(data[protocol.StreamFrameHeaderBytes:])
			send(ctx, t, session, protocol.StreamCredit{Type: protocol.StreamCreditType, StreamID: fileStreamID, Bytes: int64(len(data) - protocol.StreamFrameHeaderBytes)})
			continue
		}

		messageType, _ := protocol.MessageType(data)
		switch messageType {
		case protocol.FSReadOpenedType:
			if err := protocol.DecodeStrict(data, &opened); err != nil {
				t.Fatalf("fs.read.opened = %s", data)
			}
		case protocol.StreamCloseType:
			var closing protocol.StreamClose
			if err := protocol.DecodeStrict(data, &closing); err != nil || closing.Reason != protocol.StreamEnded {
				t.Fatalf("stream.close = %s", data)
			}
			return opened, content.Bytes()
		default:
			acknowledge(ctx, t, session, messageType, data, protocol.StreamCloseType)
		}
	}
}
