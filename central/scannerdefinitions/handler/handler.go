package handler

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	blob "github.com/stackrox/rox/central/blob/datastore"
	"github.com/stackrox/rox/central/blob/snapshot"
	"github.com/stackrox/rox/central/scannerdefinitions/file"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/buildinfo"
	"github.com/stackrox/rox/pkg/env"
	"github.com/stackrox/rox/pkg/errox"
	"github.com/stackrox/rox/pkg/features"
	"github.com/stackrox/rox/pkg/fileutils"
	"github.com/stackrox/rox/pkg/httputil"
	"github.com/stackrox/rox/pkg/httputil/proxy"
	"github.com/stackrox/rox/pkg/logging"
	"github.com/stackrox/rox/pkg/protocompat"
	"github.com/stackrox/rox/pkg/sac"
	"github.com/stackrox/rox/pkg/sync"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/rox/pkg/version"
	"google.golang.org/grpc/codes"
)

const (
	// tmpDirPattern is the pattern for the directory in which all Scanner data is written.
	tmpDirPattern = "scannerdefinitions-*"

	// scannerV2DiffFile is the name of the file which contains Scanner v2 diff data.
	scannerV2DiffFile = "diff.zip"
	// scannerV2DefsFileis the name of the file which contains offline Scanner v2 data.
	scannerV2DefsFile = "scanner-defs.zip"
	// offlineScannerV2DefsBlobName represents the blob name of offline/fallback data file for Scanner v2.
	offlineScannerV2DefsBlobName = "/offline/scanner/scanner-defs.zip"

	// scannerV4DefsPrefix helps to search the v4 offline zip bundle for CVEs
	scannerV4DefsPrefix    = "scanner-v4-defs"
	scannerV4ManifestFile  = "manifest.json"
	scannerV4VulnSubDir    = "v4/vulnerability-bundles"
	scannerV4MappingSubDir = "v4/redhat-repository-mappings"
	scannerV4MappingFile   = "mapping.zip"
	// offlineScannerV4DefsBlobName represents the blob name of offline/fallback data file for Scanner V4.
	offlineScannerV4DefsBlobName = "/offline/scanner/v4/scanner-v4-defs.zip"

	// scannerV4AcceptHeader defines the custom HTTP header to identify the content type Scanner V4 desires.
	// This is used instead of Accept, as we do not map this 1:1 with the returned content type.
	scannerV4AcceptHeader = "X-Scanner-V4-Accept"
	// scannerV4MultiBundleContentType is the custom content type representing Scanner V4 wants
	// the "multi-bundle" ZIP data returned.
	scannerV4MultiBundleContentType = "application/vnd.stackrox.scanner-v4.multi-bundle+zip"

	// tmpUploadFile is the name of the file to which uploaded data is written, temporarily.
	tmpUploadFile = "offline-defs.zip"

	defaultCleanupInterval = 4 * time.Hour
	defaultCleanupAge      = 1 * time.Hour
)

//go:generate stringer -type=updaterType
type updaterType int

const (
	mappingUpdaterType updaterType = iota
	vulnerabilityUpdaterType
	v2UpdaterType
)

var (
	scannerUpdateBaseURL *url.URL

	client = &http.Client{
		Transport: proxy.RoundTripper(),
		Timeout:   5 * time.Minute,
	}

	log = logging.LoggerForModule()

	// v4FileMapping maps a URL query parameter to its associated
	// Scanner V4 map file.
	v4FileMapping = map[string]string{
		"name2repos": "repomapping/container-name-repos-map.json",
		"repo2cpe":   "repomapping/repository-to-cpe.json",
	}
	minorVersionPattern = regexp.MustCompile(`^\d+\.\d+`)
)

type requestedUpdater struct {
	*updater
	lastRequestedTime time.Time
}

// manifest represents the manifest.json file
// containing Scanner V4 related metadata.
type manifest struct {
	Version string `json:"version"`
}

// httpHandler handles HTTP GET and POST requests for vulnerability data.
type httpHandler struct {
	// online indicates if we are in online or offline mode.
	online bool
	// updaterInterval specifies the time period between subsequent updates, in online-mode.
	updaterInterval time.Duration
	// updatersLock protects updaters.
	updatersLock sync.Mutex
	// updaters stores the various updaters which may be required.
	updaters map[string]*requestedUpdater
	// dataDir is the root directory into which all data is downloaded.
	dataDir string
	// uploadPath is the file path to which "offline data" is uploaded prior to storing in blobStore.
	// This file will be under the dataDir directory.
	uploadPath string
	// blobStore provides access to the blob storage which stores the uploaded "offline data".
	blobStore blob.Datastore

	// uploadInProgress indicates when there is
	// a scanner definitions upload (POST) already in progress.
	// This is meant to protect from concurrent uploads which may overwrite each other.
	// Concurrent uploads are not expected nor supported.
	uploadInProgress atomic.Bool
}

func init() {
	var err error
	scannerUpdateBaseURL, err = url.Parse("https://definitions.stackrox.io")
	utils.CrashOnError(err) // This is very unexpected.
}

// New creates a new http.Handler to handle vulnerability data.
func New(blobStore blob.Datastore, opts handlerOpts) http.Handler {
	dataDir, err := os.MkdirTemp("", tmpDirPattern)
	utils.CrashOnError(err) // Fundamental problem if we cannot create a temp directory.

	h := &httpHandler{
		online:          !env.OfflineModeEnv.BooleanSetting(),
		updaterInterval: env.ScannerVulnUpdateInterval.DurationSetting(),
		dataDir:         dataDir,
		uploadPath:      filepath.Join(dataDir, tmpUploadFile),
		blobStore:       blobStore,
	}

	if !h.online {
		log.Info("In offline mode: scanner definitions will not be updated automatically")
		return h
	}

	log.Info("In online mode: scanner definitions will be updated automatically")

	h.updaters = make(map[string]*requestedUpdater)
	go h.cleanUpdatersPeriodic(opts.cleanupInterval, opts.cleanupAge)

	return h
}

func (h *httpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.get(w, r)
	case http.MethodPost:
		h.post(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// openOpts are options to open most recent V4 definition files.
type openOpts struct {
	// name is a generic name to refer to the definition bundle and its content.
	name string
	// urlPath specifies the update URL path when setting up online updaters.
	urlPath string
	// fileName specifies one file from within the scanner definition archive to
	// open, instead of returning the archive itself.
	fileName string
	// vulnVersion specifies the version of the vulnerability bundle for
	// vulnerability updaters.
	vulnVersion string
	// vulnBundle specifies the vulnerability bundle name for vulnerability updaters.
	vulnBundle string
	// offlineBlobName is the name of the offline blob to use.
	offlineBlobName string
}

func (h *httpHandler) get(w http.ResponseWriter, r *http.Request) {
	// URL parameters.
	uuid := r.URL.Query().Get(`uuid`)
	fileName := r.URL.Query().Get(`file`)
	v := r.URL.Query().Get(`version`)

	ctx := r.Context()

	var uType updaterType
	var opts openOpts
	var contentType string

	switch {
	case uuid != "":
		// Scanner V2 definitions.
		uType = v2UpdaterType
		opts.name = uuid
		opts.urlPath = uuid
		opts.fileName = fileName
		opts.offlineBlobName = offlineScannerV2DefsBlobName
	case fileName != "" && v == "":
		// If only file is requested, then this is request for Scanner v4 mapping file.
		v4FileName, exists := v4FileMapping[fileName]
		if !exists {
			writeErrorNotFound(w)
			return
		}
		uType = mappingUpdaterType
		opts.name = fileName
		opts.fileName = v4FileName
		opts.offlineBlobName = offlineScannerV4DefsBlobName
	case fileName == "" && v != "":
		// If only version is provided, this is for Scanner V4 vuln file
		if version.GetVersionKind(v) == version.NightlyKind {
			// get dev for nightly at this moment
			v = "dev"
		}
		uType = vulnerabilityUpdaterType
		bundle := "vulns.json.zst"
		contentType = "application/zstd"
		if r.Header.Get(scannerV4AcceptHeader) == scannerV4MultiBundleContentType {
			bundle = "vulnerabilities.zip"
			contentType = "application/zip"
		}
		opts.name = v
		opts.urlPath = path.Join(v, bundle)
		opts.vulnVersion = v
		opts.vulnBundle = bundle
		opts.offlineBlobName = offlineScannerV4DefsBlobName
	default:
		writeErrorBadRequest(w)
		return
	}

	f, err := h.openDefinitions(ctx, uType, opts)
	if err != nil {
		writeErrorForFile(w, err, opts.name)
		return
	}

	if f == nil {
		writeErrorNotFound(w)
		return
	}

	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}

	defer utils.IgnoreError(f.Close)
	serveContent(w, r, f.Name(), f.modTime, f)
}

func (h *httpHandler) openDefinitions(ctx context.Context, t updaterType, opts openOpts) (*vulDefFile, error) {
	log.Debugf("Fetching scanner V4 (online: %t): type %s: options: %#v", h.online, t, opts)

	file, err := h.openOfflineDefinitions(ctx, t, opts)
	if !h.online {
		return file, err
	}
	if err != nil {
		log.Debugf("Failed to access offline file (ignore the message if no "+
			"offline bundle has been uploaded): %v", err)
	}

	offlineFile := file

	defer func() {
		if offlineFile != nil {
			_ = offlineFile.Close()
		}
	}()

	file, err = h.openOnlineDefinitions(ctx, t, opts)
	if err != nil {
		return nil, err
	}

	// If the offline files are newer, return them instead.
	if offlineFile != nil && offlineFile.modTime.After(file.modTime) {
		_ = file.Close()
		// Set nil to protect the deferred close.
		file, offlineFile = offlineFile, nil
	}

	return file, err
}

// openOfflineDefinitions gets desired offline file from compressed bundle.
func (h *httpHandler) openOfflineDefinitions(ctx context.Context, t updaterType, opts openOpts) (*vulDefFile, error) {
	log.Debugf("Getting v4 offline data for updater: type %s: options: %#v", t, opts)
	openedFile, err := h.openOfflineBlob(ctx, opts.offlineBlobName)
	if err != nil {
		return nil, fmt.Errorf("opening offline definitions: %s: %w",
			opts.offlineBlobName, err)
	}
	if openedFile == nil {
		log.Warnf("Blob %s does not exist", opts.offlineBlobName)
		return nil, nil
	}
	var offlineFile *vulDefFile
	switch t {
	case v2UpdaterType:
		if opts.fileName == "" {
			offlineFile = openedFile
			break
		}
		fallthrough
	case mappingUpdaterType:
		// openFromArchive will copy the contents of opts.fileName from openedFile to
		// targetFile. Because of this, openedFile is not needed outside this function,
		// so close it here.
		defer utils.IgnoreError(openedFile.Close)
		// search mapping file
		fileName := filepath.Base(opts.fileName)
		targetFile, _, err := h.openFromArchive(openedFile.Name(), fileName)
		if err != nil {
			return nil, err
		}
		offlineFile = &vulDefFile{File: targetFile, modTime: openedFile.modTime}
	case vulnerabilityUpdaterType:
		// openFromArchive will copy the contents of opts.fileName from openedFile to
		// mf. Because of this, openedFile is not needed outside this function,
		// so close it here.
		defer utils.IgnoreError(openedFile.Close)
		// check version information in manifest
		mf, _, err := h.openFromArchive(openedFile.Name(), scannerV4ManifestFile)
		if err != nil {
			return nil, err
		}
		offlineV, err := getOfflineFileVersion(mf)
		if err != nil {
			return nil, err
		}
		defer utils.IgnoreError(mf.Close)

		if offlineV != minorVersionPattern.FindString(opts.vulnVersion) && (opts.vulnVersion != "dev" || buildinfo.ReleaseBuild) {
			msg := fmt.Sprintf("failed to get offline vuln file, uploaded file is version: %s and requested file version is: %s", offlineV, opts.vulnVersion)
			log.Errorf(msg)
			return nil, errors.New(msg)
		}

		vulns, _, err := h.openFromArchive(openedFile.Name(), opts.vulnBundle)
		if err != nil {
			return nil, err
		}
		offlineFile = &vulDefFile{File: vulns, modTime: openedFile.modTime}
	default:
		return nil, fmt.Errorf("unknown updater type: %s", t)
	}

	return offlineFile, nil
}

func (h *httpHandler) openOfflineBlob(ctx context.Context, blobName string) (*vulDefFile, error) {
	snap, err := snapshot.TakeBlobSnapshot(sac.WithAllAccess(ctx), h.blobStore, blobName)
	if err != nil {
		// If the blob does not exist, return no reader.
		if errors.Is(err, snapshot.ErrBlobNotExist) {
			return nil, nil
		}
		log.Warnf("Cannnot take a snapshot of Blob %q: %v", blobName, err)
		return nil, err
	}
	modTime := time.Time{}
	if t := protocompat.NilOrTime(snap.GetBlob().ModifiedTime); t != nil {
		modTime = *t
	}
	return &vulDefFile{snap.File, modTime, snap.Close}, nil
}

// openOnlineDefinitions gets desired "online" file, which is pulled and managed
// by the updater.
func (h *httpHandler) openOnlineDefinitions(_ context.Context, t updaterType, opts openOpts) (*vulDefFile, error) {
	u := h.getUpdater(t, opts.urlPath)
	// Ensure the updater is running.
	u.Start()
	openedFile, onlineTime, err := u.file.Open()
	if err != nil {
		return nil, err
	}
	if openedFile == nil {
		return nil, fmt.Errorf("scanner V4 %s file %s not found", t, opts.urlPath)
	}
	log.Debugf("Compressed data file is available: %s", openedFile.Name())
	switch t {
	case v2UpdaterType:
		if opts.fileName == "" {
			return &vulDefFile{File: openedFile, modTime: onlineTime}, nil
		}
		fallthrough
	case mappingUpdaterType:
		// openFromArchive will copy the contents of opts.fileName from openedFile to
		// targetFile. Because of this, openedFile is not needed outside this function,
		// so close it here.
		defer utils.IgnoreError(openedFile.Close)
		targetFile, _, err := h.openFromArchive(openedFile.Name(), opts.fileName)
		if err != nil {
			return nil, err
		}
		return &vulDefFile{File: targetFile, modTime: onlineTime}, nil
	case vulnerabilityUpdaterType:
		return &vulDefFile{File: openedFile, modTime: onlineTime}, nil
	}
	return nil, fmt.Errorf("unknown Scanner V4 updater type: %s", t)
}

// getUpdater gets or creates an updater for the scanner definitions identified
// by the given updater type and a URL path to the definitions file. If the
// updater was created, it is no started here, callers are expected to start it.
func (h *httpHandler) getUpdater(t updaterType, urlPath string) *requestedUpdater {
	h.updatersLock.Lock()
	defer h.updatersLock.Unlock()

	fileName := strings.ReplaceAll(filepath.Join(t.String(), urlPath), "/", "-")
	updater, exists := h.updaters[fileName]
	if !exists {
		var updateURL *url.URL
		var ext string
		switch t {
		case mappingUpdaterType:
			updateURL = scannerUpdateBaseURL.JoinPath(scannerV4MappingSubDir, scannerV4MappingFile)
			ext = ".zip"
		case vulnerabilityUpdaterType:
			updateURL = scannerUpdateBaseURL.JoinPath(scannerV4VulnSubDir, urlPath)
			ext = ".json.zst"
		default: // uuid
			updateURL = scannerUpdateBaseURL.JoinPath(urlPath, scannerV2DiffFile)
			ext = ".zip"
		}
		filePath := filepath.Join(h.dataDir, fileName)
		// Use a default extension if the URL path does not contain one.
		if filepath.Ext(fileName) == "" {
			filePath += ext
		}
		updater = &requestedUpdater{
			updater: newUpdater(file.New(filePath), client, updateURL.String(), h.updaterInterval),
		}
		h.updaters[fileName] = updater
	}

	updater.lastRequestedTime = time.Now()
	return updater
}

func (h *httpHandler) post(w http.ResponseWriter, r *http.Request) {
	// Swap will set h.uploadInProgress to true and return the previous value.
	// If it was previously true, then there is already an upload in progress,
	// so we should abort the operation.
	if h.uploadInProgress.Swap(true) {
		httputil.WriteGRPCStyleError(w, codes.Aborted, errors.New("scanner definitions upload already in progress"))
		return
	}
	// There are no other uploads in progress at this point.
	// Once we exit this function, the upload is no longer in progress.
	defer h.uploadInProgress.Store(false)

	// Copy the request body into the filesystem.
	// If the file at h.uploadPath doesn't exist yet, it will be created.
	if err := fileutils.CopySrcToFile(h.uploadPath, r.Body); err != nil {
		httputil.WriteGRPCStyleError(w, codes.Internal, errors.Wrap(err, "copying uploaded scanner definitions"))
		return
	}

	if features.ScannerV4.Enabled() {
		if err := h.validateV4DefsVersion(); err != nil {
			httputil.WriteGRPCStyleError(w, codes.InvalidArgument, err)
			return
		}
	}
	if err := h.handleZipContentsFromVulnDump(r.Context()); err != nil {
		httputil.WriteGRPCStyleError(w, codes.InvalidArgument, err)
		return
	}

	_, _ = w.Write([]byte("Successfully stored scanner vulnerability definitions"))
}

func (h *httpHandler) validateV4DefsVersion() error {
	zipR, err := zip.OpenReader(h.uploadPath)
	if err != nil {
		return errors.Wrap(err, "couldn't open file as zip")
	}
	defer utils.IgnoreError(zipR.Close)

	for _, zipF := range zipR.File {
		if strings.HasPrefix(zipF.Name, scannerV4DefsPrefix) {
			defs, size, err := h.openFromArchive(h.uploadPath, zipF.Name)
			if err != nil {
				return errors.Wrap(err, "couldn't open v4 offline defs manifest.json")
			}
			defer utils.IgnoreError(defs.Close)
			// Use readFromArchive, as the defs file was already closed via openFromArchive.
			mf, err := h.readFromArchive(defs, size, scannerV4ManifestFile)
			if err != nil {
				return errors.Wrap(err, "couldn't open v4 offline defs manifest.json")
			}
			defer utils.IgnoreError(mf.Close)
			offlineV, err := getOfflineFileVersion(mf)
			if err != nil {
				return errors.Wrap(err, "couldn't get v4 offline defs version")
			}
			v := minorVersionPattern.FindString(version.GetMainVersion())
			if offlineV != "dev" && offlineV != v {
				msg := fmt.Sprintf("failed to upload offline file bundle, uploaded file is version: %s and system version is: %s; "+
					"please upload an offline bundle version: %s, consider using command roxctl scanner download-db", offlineV, version.GetMainVersion(), v)
				log.Errorf(msg)
				return errors.New(msg)
			}
		}
	}
	return nil
}

func (h *httpHandler) handleZipContentsFromVulnDump(ctx context.Context) error {
	zipR, err := zip.OpenReader(h.uploadPath)
	if err != nil {
		return errors.Wrap(err, "couldn't open file as zip")
	}
	defer utils.IgnoreError(zipR.Close)
	var count int
	// It is expected a ZIP file be uploaded with both Scanner V2 and V4 vulnerability definitions.
	// scanner-defs.zip contains data required by Scanner V2.
	// scanner-v4-defs-*.zip contains data required by Scanner v4.
	// In the future, we may decide to support other files (like we have in the past), which is why we
	// expect this ZIP of a single ZIP.
	for _, zipF := range zipR.File {
		if zipF.Name == scannerV2DefsFile {
			if err := h.handleScannerDefsFile(ctx, zipF, offlineScannerV2DefsBlobName); err != nil {
				return errors.Wrap(err, "couldn't handle scanner-defs sub file")
			}
			count++
			continue
		}
		if strings.HasPrefix(zipF.Name, scannerV4DefsPrefix) {
			if err := h.handleScannerDefsFile(ctx, zipF, offlineScannerV4DefsBlobName); err != nil {
				return errors.Wrap(err, "couldn't handle scanner-v4-defs sub file")
			}
			log.Debugf("Successfully processed file: %s", zipF.Name)
			count++
		}
		// Ignore any other files which may be in the ZIP.
	}
	if count > 0 {
		return nil
	}
	return errors.New("scanner defs file not found in upload zip; wrong zip uploaded?")
}

func (h *httpHandler) handleScannerDefsFile(ctx context.Context, zipF *zip.File, blobName string) error {
	r, err := zipF.Open()
	if err != nil {
		return errors.Wrap(err, "opening ZIP reader")
	}
	defer utils.IgnoreError(r.Close)

	// POST requests only update the offline feed.
	b := &storage.Blob{
		Name:         blobName,
		LastUpdated:  protocompat.TimestampNow(),
		ModifiedTime: protocompat.TimestampNow(),
		Length:       zipF.FileInfo().Size(),
	}

	if err := h.blobStore.Upsert(sac.WithAllAccess(ctx), b, r); err != nil {
		return errors.Wrap(err, "writing scanner definitions")
	}

	return nil
}

// openFromArchive returns the associated file for the given name within the ZIP archiveFile
// along with the file size.
//
// The returned file struct has a file descriptor allocated on the filesystem outside the ZIP, but
// its name is removed. Meaning: as soon as the file struct is closed, the data will be
// freed in filesystem by the OS. That also means there should not be any OS operations
// done on the returned file.
func (h *httpHandler) openFromArchive(archiveFile string, fileName string) (*os.File, int64, error) {
	zipReader, err := zip.OpenReader(archiveFile)
	if err != nil {
		return nil, 0, errors.Wrap(err, "opening zip archive")
	}
	defer utils.IgnoreError(zipReader.Close)

	return h.openFromZipReader(&zipReader.Reader, fileName)
}

// readFromArchive returns the associated file for the given name within the ZIP archive.
//
// The returned file struct has a file descriptor allocated on the filesystem outside the ZIP, but
// its name is removed. Meaning: as soon as the file struct is closed, the data will be
// freed in filesystem by the OS. That also means there should not be any OS operations
// done on the returned file.
func (h *httpHandler) readFromArchive(archive io.ReaderAt, size int64, fileName string) (*os.File, error) {
	zipReader, err := zip.NewReader(archive, size)
	if err != nil {
		return nil, errors.Wrap(err, "reading zip archive")
	}

	f, _, err := h.openFromZipReader(zipReader, fileName)
	return f, err
}

// openFromZipReader does the work for readFromArchive and openFromArchive.
// It should **not** be used outside of those functions.
func (h *httpHandler) openFromZipReader(zipReader *zip.Reader, fileName string) (*os.File, int64, error) {
	zipFile, err := zipReader.Open(fileName)
	if err != nil {
		return nil, 0, errors.Wrap(err, "extracting file")
	}
	defer utils.IgnoreError(zipFile.Close)

	// Create a temporary file and remove it for the OS to clean up once the
	// struct is closed.
	//
	// Ensure the file extension stays intact (via the *- prefix) so the HTTP server
	// can automatically pick up the Content-Type.
	//
	// Also, replace / with - to account for the mapping files, as
	// forward slash is invalid in the pattern accepted by os.CreateTemp.
	tmpFilePattern := "*-" + strings.ReplaceAll(fileName, "/", "-")
	tmpFile, err := os.CreateTemp(h.dataDir, tmpFilePattern)
	if err != nil {
		return nil, 0, errors.Wrap(err, "opening temporary file")
	}
	defer func() {
		_ = os.Remove(tmpFile.Name())
	}()
	var success bool
	defer func() {
		// If this function is unsuccessful, then close the struct.
		if !success {
			utils.IgnoreError(tmpFile.Close)
		}
	}()

	// Extract the file and copy contents to the temporary file, notice we
	// intentionally don't Sync(), to benefit from filesystem caching.
	size, err := io.Copy(tmpFile, zipFile)
	if err != nil {
		return nil, 0, errors.Wrap(err, "writing to temporary file")
	}

	// Reset for caller's convenience.
	_, err = tmpFile.Seek(0, io.SeekStart)
	if err != nil {
		return nil, 0, errors.Wrap(err, "setting offset for temporary file")
	}

	success = true
	return tmpFile, size, nil
}

func getOfflineFileVersion(mf *os.File) (string, error) {
	var m manifest
	err := json.NewDecoder(mf).Decode(&m)
	if err != nil {
		return "", err
	}
	return m.Version, nil
}

func serveContent(w http.ResponseWriter, r *http.Request, name string, modTime time.Time, content io.ReadSeeker) {
	log.Debugf("Serving vulnerability definitions from %s", filepath.Base(name))
	http.ServeContent(w, r, name, modTime, content)
}

func writeErrorNotFound(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("No scanner definitions found"))
}

func writeErrorBadRequest(w http.ResponseWriter) {
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte("at least one of file or uuid must be specified"))
}

func writeErrorForFile(w http.ResponseWriter, err error, path string) {
	if errox.IsAny(err, fs.ErrNotExist, snapshot.ErrBlobNotExist) {
		writeErrorNotFound(w)
		return
	}

	httputil.WriteGRPCStyleErrorf(w, codes.Internal, "could not read vulnerability definition %s: %v", filepath.Base(path), err)
}

func (h *httpHandler) cleanUpdatersPeriodic(cleanupInterval, cleanupAge *time.Duration) {
	interval := defaultCleanupInterval
	if cleanupInterval != nil {
		interval = *cleanupInterval
	}
	age := defaultCleanupAge
	if cleanupAge != nil {
		age = *cleanupAge
	}

	t := time.NewTicker(interval)
	for range t.C {
		h.cleanupUpdaters(age)
	}
}

func (h *httpHandler) cleanupUpdaters(cleanupAge time.Duration) {
	now := time.Now()

	h.updatersLock.Lock()
	defer h.updatersLock.Unlock()

	for id, updatingHandler := range h.updaters {
		if now.Sub(updatingHandler.lastRequestedTime) > cleanupAge {
			// Updater has not been requested for a long time.
			// Clean it up.
			updatingHandler.Stop()
			delete(h.updaters, id)
		}
	}
}
