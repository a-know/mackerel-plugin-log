package mplog

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/jessevdk/go-flags"
	mp "github.com/mackerelio/go-mackerel-plugin"
	"github.com/mackerelio/golib/pluginutil"
	"github.com/mattn/go-encoding"
	"github.com/mattn/go-zglob"
	"github.com/natefinch/atomic"
	enc "golang.org/x/text/encoding"
)

// overwritten with syscall.SIGTERM on unix environment (see check-log_unix.go)
var defaultSignal = os.Interrupt

type logOpts struct {
	Prefix           string   `long:"metric-key-prefix" value-name:"PREFIX" description:"Metric key prefix"`
	LogFile          string   `short:"f" long:"file" value-name:"FILE" description:"Path to log file"`
	Pattern          []string `short:"p" long:"pattern" required:"true" value-name:"PAT" description:"Pattern to search for. If specified multiple, they will be treated together with the AND operator"`
	Exclude          string   `short:"E" long:"exclude" value-name:"PAT" description:"Pattern to exclude from matching"`
	CaseInsensitive  bool     `short:"i" long:"icase" description:"Run a case insensitive match"`
	Encoding         string   `long:"encoding" description:"Encoding of log file"`
	patternReg       []*regexp.Regexp
	excludeReg       *regexp.Regexp
	fileListFromGlob []string
	origArgs         []string
	decoder          *enc.Decoder

	testHookNewBufferedReader func(r io.Reader) *bufio.Reader
}

// MetricKeyPrefix interface for PluginWithPrefix
func (opts *logOpts) MetricKeyPrefix() string {
	if opts.Prefix == "" {
		opts.Prefix = "log"
	}
	return opts.Prefix
}

// GraphDefinition interface for mackerelplugin
func (opts *logOpts) GraphDefinition() map[string]mp.Graphs {
	labelPrefix := strings.Title(opts.Prefix)
	_, filename := filepath.Split(opts.LogFile)
	filename = strings.Replace(filename, ".", "-", -1)
	return map[string]mp.Graphs{
		filename: {
			Label: labelPrefix + filename + " detect Num (" + strings.Join(opts.Pattern, ",") + ")",
			Unit:  "integer",
			Metrics: []mp.Metrics{
				{Name: "detect_num", Label: "Detect Lines"},
			},
		},
	}
}

// Do the plugin
func Do() {
	logOpts, err := parseArgs(os.Args)
	if err != nil {
		os.Exit(1)
	}

	err = logOpts.prepare()
	if err != nil {
		os.Exit(1)
	}

	mp.NewMackerelPlugin(logOpts).Run()
}

func (opts *logOpts) prepare() error {
	if opts.LogFile == "" {
		fmt.Fprint(os.Stderr, "No log file specified")
		os.Exit(1)
	}

	var err error
	var reg *regexp.Regexp
	for _, ptn := range opts.Pattern {
		if reg, err = regCompileWithCase(ptn, opts.CaseInsensitive); err != nil {
			fmt.Fprint(os.Stderr, "pattern is invalid")
			os.Exit(1)
		}
		opts.patternReg = append(opts.patternReg, reg)
	}

	if opts.Exclude != "" {
		opts.excludeReg, err = regCompileWithCase(opts.Exclude, opts.CaseInsensitive)
		if err != nil {
			fmt.Fprint(os.Stderr, "exclude pattern is invalid")
			os.Exit(1)
		}
	}

	if opts.LogFile != "" {
		opts.fileListFromGlob, err = zglob.Glob(opts.LogFile)
		// unless --missing specified, we should ignore file not found error
		if err != nil && err != os.ErrNotExist {
			fmt.Fprint(os.Stderr, "invalid glob for --file")
			os.Exit(1)
		}
	}

	return nil
}

func regCompileWithCase(ptn string, caseInsensitive bool) (*regexp.Regexp, error) {
	if caseInsensitive {
		ptn = "(?i)" + ptn
	}
	return regexp.Compile(ptn)
}

func parseArgs(args []string) (*logOpts, error) {
	origArgs := make([]string, len(args))
	copy(origArgs, args)
	opts := &logOpts{}
	_, err := flags.ParseArgs(opts, args)
	opts.origArgs = origArgs
	return opts, err
}

func (opts *logOpts) FetchMetrics() (map[string]float64, error) {

	var missingFiles []string

	var ret map[string]float64
	if opts.LogFile != "" && len(opts.fileListFromGlob) == 0 {
		missingFiles = append(missingFiles, opts.LogFile)
	}

	for _, f := range append(opts.fileListFromGlob) {
		_, err := os.Stat(f)
		if err != nil {
			missingFiles = append(missingFiles, f)
			continue
		}
		ret, err = opts.searchLog(f)
		if err != nil {
			return nil, err
		}
	}

	return ret, nil
}

func (opts *logOpts) searchLog(logFile string) (map[string]float64, error) {
	ret := make(map[string]float64)

	workdir := pluginutil.PluginWorkDir()
	stateDir := filepath.Join(workdir, "mackerel-plugin-log")
	stateFile := getStateFile(stateDir, logFile, opts.origArgs)
	skipBytes, inode, isFirstCheck := int64(0), uint(0), false

	s, err := getBytesToSkip(stateFile)
	if err != nil {
		if err != errValidStateFileNotFound {
			return ret, err
		}
		isFirstCheck = true
	}
	skipBytes = s

	i, err := getInode(stateFile)
	if err != nil {
		return ret, err
	}
	inode = i

	f, err := os.Open(logFile)
	if err != nil {
		return ret, err
	}
	defer f.Close()

	oldf, err := openOldFile(logFile, &state{SkipBytes: skipBytes, Inode: inode})
	if err != nil {
		return ret, err
	}
	defer oldf.Close()

	stat, err := f.Stat()
	if err != nil {
		return ret, err
	}

	if isFirstCheck {
		skipBytes = stat.Size()
	}

	rotated := false
	if stat.Size() < skipBytes {
		rotated = true
	} else if skipBytes > 0 {
		f.Seek(skipBytes, 0)
	}

	var r io.Reader = f
	var oldr io.Reader = oldf
	if opts.Encoding != "" {
		e := encoding.GetEncoding(opts.Encoding)
		if e == nil {
			return ret, fmt.Errorf("unknown encoding:" + opts.Encoding)
		}
		opts.decoder = e.NewDecoder()
	}

	matchNum, readBytes, errLines, err := opts.searchReader(r)
	if err != nil {
		return ret, err
	}

	if oldf != nil {
		// search old file
		var oldErrLines string
		// ignore readBytes under the premise that the old file will never be updated.
		oldMatchNum, _, oldErrLines, err := opts.searchReader(oldr)
		if err != nil {
			return ret, err
		}
		matchNum += oldMatchNum
		errLines += oldErrLines
	}

	if rotated {
		skipBytes = readBytes
	} else {
		skipBytes += readBytes
	}

	err = saveState(stateFile, &state{SkipBytes: skipBytes, Inode: detectInode(stat)})
	if err != nil {
		log.Printf("writeByteToSkip failed: %s\n", err.Error())
	}

	ret["detect_num"] = float64(matchNum)

	return ret, nil
}

func newBufferedReader(r io.Reader) *bufio.Reader {
	return bufio.NewReader(r)
}

func (opts *logOpts) searchReader(rdr io.Reader) (matchNum, readBytes int64, errLines string, err error) {
	newReader := opts.testHookNewBufferedReader
	if newReader == nil {
		newReader = newBufferedReader
	}

	var errLinesBuilder strings.Builder
	r := newReader(rdr)
	for {
		lineBytes, rErr := r.ReadBytes('\n')
		if rErr != nil {
			if rErr != io.EOF {
				err = rErr
			}
			break
		}
		readBytes += int64(len(lineBytes))

		if opts.decoder != nil {
			lineBytes, err = opts.decoder.Bytes(lineBytes)
			if err != nil {
				break
			}
		}
		line := strings.Trim(string(lineBytes), "\r\n")
		if matched, _ := opts.match(line); matched {
			matchNum++
			errLinesBuilder.WriteString(line)
			errLinesBuilder.WriteString("\n")
		}
	}

	errLines = errLinesBuilder.String()
	return
}

func (opts *logOpts) match(line string) (bool, []string) {
	var matches []string
	for _, pReg := range opts.patternReg {
		eReg := opts.excludeReg

		matches = pReg.FindStringSubmatch(line)
		if len(matches) == 0 || (eReg != nil && eReg.MatchString(line)) {
			return false, nil
		}
	}
	return true, matches
}

type state struct {
	SkipBytes int64 `json:"skip_bytes"`
	Inode     uint  `json:"inode"`
}

func loadState(fname string) (*state, error) {
	state := &state{}
	b, err := ioutil.ReadFile(fname)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return state, err
	}
	err = json.Unmarshal(b, state)
	if err != nil {
		// this json unmarshal error will be ignored by callers
		log.Printf("failed to loadState (will be ignored): %s", err)
		return nil, errStateFileCorrupted
	}
	return state, nil
}

var stateRe = regexp.MustCompile(`^([a-zA-Z]):[/\\]`)

func getStateFile(stateDir, f string, args []string) string {
	return filepath.Join(
		stateDir,
		fmt.Sprintf(
			"%s-%x.json",
			stateRe.ReplaceAllString(f, `$1`+string(filepath.Separator)),
			md5.Sum([]byte(strings.Join(args, " "))),
		),
	)
}

var errValidStateFileNotFound = fmt.Errorf("state file not found, or corrupted")
var errStateFileCorrupted = fmt.Errorf("state file is corrupted")

func getBytesToSkip(f string) (int64, error) {
	state, err := loadState(f)
	// Do not fallback to old status file when JSON file is corrupted
	if err == errStateFileCorrupted {
		return 0, errValidStateFileNotFound
	}
	if err != nil {
		return 0, err
	}
	if state != nil {
		// json file exists
		return state.SkipBytes, nil
	}
	// Fallback to read old style status file
	// for backward compatibility.
	// Once saved as new style file, the following will be unreachable.
	oldf := strings.TrimSuffix(f, ".json")
	return getBytesToSkipOld(oldf)
}

func getBytesToSkipOld(f string) (int64, error) {
	b, err := ioutil.ReadFile(f)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, errValidStateFileNotFound
		}
		return 0, err
	}

	i, err := strconv.ParseInt(strings.Trim(string(b), " \r\n"), 10, 64)
	if err != nil {
		log.Printf("failed to getBytesToSkip (ignoring): %s", err)
	}
	return i, nil
}

func getInode(f string) (uint, error) {
	state, err := loadState(f)
	// ignore corrupted json
	if err == errStateFileCorrupted {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if state != nil {
		// json file exists
		return state.Inode, nil
	}
	return 0, nil
}

func saveState(f string, state *state) error {
	b, _ := json.Marshal(state)
	if err := os.MkdirAll(filepath.Dir(f), 0755); err != nil {
		return err
	}
	return atomic.WriteFile(f, bytes.NewReader(b))
}

var errFileNotFoundByInode = fmt.Errorf("old file not found")

func findFileByInode(inode uint, dir string) (string, error) {
	fis, err := ioutil.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, fi := range fis {
		if detectInode(fi) == inode {
			return filepath.Join(dir, fi.Name()), nil
		}
	}
	return "", errFileNotFoundByInode
}

func openOldFile(f string, state *state) (*os.File, error) {
	fi, err := os.Stat(f)
	if err != nil {
		return nil, err
	}
	inode := detectInode(fi)
	if state.Inode > 0 && state.Inode != inode {
		if oldFile, err := findFileByInode(state.Inode, filepath.Dir(f)); err == nil {
			oldf, err := os.Open(oldFile)
			if err != nil {
				return nil, err
			}
			oldfi, _ := oldf.Stat()
			if oldfi.Size() > state.SkipBytes {
				oldf.Seek(state.SkipBytes, io.SeekStart)
				return oldf, nil
			}
		} else if err != errFileNotFoundByInode {
			return nil, err
		}
		// just ignore the process of searching old file if errFileNotFoundByInode
	}
	return nil, nil
}

func detectInode(fi os.FileInfo) uint {
	defaultSignal = syscall.SIGTERM

	if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint(stat.Ino)
	}
	return 0
}
