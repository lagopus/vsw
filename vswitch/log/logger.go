//
// Copyright 2017-2019 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package log

/*
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "logger_internal.h"

extern void vsw_log_debug_all();
extern void vsw_log_debug_none();
extern void vsw_log_debug_enable(int);
extern void vsw_log_debug_disable(int);
extern void vsw_log_verbose(bool);
extern void vsw_log_set_level(vsw_log_level_t);
extern void vsw_log_set_debug_level(uint32_t, uint8_t);
*/
import "C"

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"log/syslog"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"
	"unsafe"
)

// LogConfig defines a configuration for logging facility.
type loggerConfig struct {
	Logging LogConfig
}

type LogConfig struct {
	Log      string   `toml:"log"`      // "syslog", "stdout", "file", or "none"
	Syslogd  string   `toml:"syslogd"`  // Network address for syslogd (e.g. "localhost:627")
	Network  string   `toml:"network"`  // "tcp" or "udp"
	Tag      string   `toml:"tag"`      // Tag for syslog
	Facility string   `toml:"facility"` // Facility used for syslog (e.g. "LOG_USER")
	Logfile  string   `toml:"logfile"`  // Filename for log file (used for "file")
	Verbose  bool     `toml:"verbose"`  // If enabled, prints filename and line number (e.g. "file.go:23")
	Level    string   `toml:"level"`    // Minimum level to log ("fatal", "error", "warning", or "info")
	Debugs   []string `toml:"debugs"`   // A slice of modules to debug. If set to "*", debugs all modules.
}

func (lc LogConfig) String() string {
	str := ""
	s := reflect.ValueOf(&lc).Elem()
	typeOfT := s.Type()
	for i := 0; i < s.NumField(); i++ {
		f := s.Field(i)
		str += fmt.Sprintf("%s=%v ", typeOfT.Field(i).Name, f.Interface())
	}
	return str
}

const (
	Ostdout = "stdout"
	Osyslog = "syslog"
	Ofile   = "file"
	Onone   = "none"

	defaultLoggerName = "unknown"
	defaultLoggerID   = 0
)

const (
	DefaultLog        = Ostdout                           // "syslog", "stdout", or "file"
	DefaultSyslogd    = ""                                // Default syslog daemon
	DefaultNetwork    = ""                                // Default network protocol
	DefaultTag        = "lagopus"                         // Default tag for syslog
	DefaultFacility   = "LOG_USER"                        // Default facility for syslog
	DefaultLogfile    = "/var/log/lagopus.log"            // Default file name for log file
	DefaultLogFlag    = log.LstdFlags | log.Lmicroseconds // Default flag for log.Logger
	DefaultLevel      = "debug"                           // Default Log Level (anything up to info level)
	DefaultDebugLevel = 0                                 // Default Debug Level
)

type Level int

const (
	Lfatal   = Level(C.VSW_LOG_LEVEL_FATAL)   // system is unsuable
	Lerror   = Level(C.VSW_LOG_LEVEL_ERROR)   // error conditions
	Lwarning = Level(C.VSW_LOG_LEVEL_WARNING) // warning conditions
	Linfo    = Level(C.VSW_LOG_LEVEL_INFO)    // informational message
	Ldebug   = Level(C.VSW_LOG_LEVEL_DEBUG)   // debug-level message
)

func (l Level) String() string {
	m := map[Level]string{
		Lfatal:   "fatal",
		Lerror:   "error",
		Lwarning: "warning",
		Linfo:    "info",
		Ldebug:   "debug",
	}
	return m[l]
}

var levelString = map[string]Level{
	"fatal":   Lfatal,
	"error":   Lerror,
	"warning": Lwarning,
	"info":    Linfo,
	"debug":   Ldebug,
}

const (
	tagFatal   = "[FATAL]"
	tagError   = "[ERROR]"
	tagWarning = "[WARN ]"
	tagInfo    = "[INFO ]"
	tagDebug   = "[DEBUG]"
)

type logManager struct {
	mutex          sync.Mutex
	level          Level
	debug          uint8
	modules        map[string]*Logger
	ids            [C.VSW_LOGGER_MAX_MODULES]*Logger
	debugAll       bool
	modulesToDebug map[string]struct{}
	file           *os.File
	cl             *log.Logger // *log.Logger for C
	dbg            func(string) error
	info           func(string) error
	warning        func(string) error
	err            func(string) error

	*log.Logger
	*syslog.Writer
}

// TODO
//
// We need to have Logger initialized before Init is even being called.
// Rationale here is modules may need to output messages in their init
// funtions upon any failure.
//
// For now, we let modules output to the stdout before Init.
//
// To resolve the problem properly, we should buffer all logging before Init
// is called. Once the initialization is completed, we should output all buffered
// logging before Init.
//
// Maybe we should use strings.Builder to buffer the log until Init is called.
//

var logMgr = &logManager{
	level:    levelString[DefaultLevel],
	modules:  make(map[string]*Logger),
	debugAll: false,
	cl:       log.New(os.Stdout, "", 0),
	Logger:   log.New(os.Stdout, "", DefaultLogFlag),
}

// Logger is logging facility to be used by any entity in Lagopus.
type Logger struct {
	mutex        sync.Mutex
	name         string
	prefix       string
	debug        uint8
	id           int
	debugEnabled bool
	mgr          *logManager
}

var DefaultLogConfig = LogConfig{
	Log:      DefaultLog,
	Syslogd:  DefaultSyslogd,
	Network:  DefaultNetwork,
	Tag:      DefaultTag,
	Facility: DefaultFacility,
	Logfile:  DefaultLogfile,
	Level:    DefaultLevel,
	Debugs:   []string{},
}

func openSyslog(c *LogConfig) error {
	var facilities = map[string]syslog.Priority{
		"LOG_USER":   syslog.LOG_USER,
		"LOG_SYSLOG": syslog.LOG_SYSLOG,
		"LOG_LOCAL0": syslog.LOG_LOCAL0,
		"LOG_LOCAL1": syslog.LOG_LOCAL1,
		"LOG_LOCAL2": syslog.LOG_LOCAL2,
		"LOG_LOCAL3": syslog.LOG_LOCAL3,
		"LOG_LOCAL4": syslog.LOG_LOCAL4,
		"LOG_LOCAL5": syslog.LOG_LOCAL5,
		"LOG_LOCAL6": syslog.LOG_LOCAL6,
		"LOG_LOCAL7": syslog.LOG_LOCAL7,
	}

	priority, ok := facilities[c.Facility]
	if !ok {
		return fmt.Errorf("Unknown syslog facility: %v", c.Facility)
	}
	priority |= syslog.LOG_INFO

	writer, err := syslog.Dial(c.Network, c.Syslogd, priority, c.Tag)
	if err != nil {
		return err
	}

	logMgr.Logger.SetOutput(writer)
	logMgr.cl.SetOutput(writer)
	logMgr.Writer = writer

	return nil
}

func openFile(c *LogConfig) error {
	f, err := os.OpenFile(c.Logfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	logMgr.Logger.SetOutput(f)
	logMgr.cl.SetOutput(f)
	logMgr.file = f

	return nil
}

// Init initialize logging facility based on configuration.
// In the case of any failure, it returns error.
//
// If the logging facility is already being initialized, it closes
// the existing ones, e.g. if the log file is opened, the file is closed
// first. Even the path to the log file hasn't changed, the logging facility
// closes the file, i.e. it reopens the same file.
func Init(c *LogConfig) error {
	logMgr.mutex.Lock()
	defer logMgr.mutex.Unlock()

	if c == nil {
		c = &DefaultLogConfig
	}

	if level, ok := levelString[c.Level]; ok {
		logMgr.level = level
		C.vsw_log_set_level(C.vsw_log_level_t(level))
	} else {
		return fmt.Errorf("Unknown logging level: %v", c.Level)
	}

	// Close if file is already opened first
	if f := logMgr.file; f != nil {
		defer func() {
			f.Close()
		}()
		logMgr.file = nil
	}

	// Close if alrady connected to syslogd
	if w := logMgr.Writer; w != nil {
		defer func() {
			w.Close()
		}()
		logMgr.Writer = nil
	}

	switch l := c.Log; l {
	case Ostdout:
		logMgr.Logger.SetOutput(os.Stdout)
		logMgr.cl.SetOutput(os.Stdout)
		logMgr.setDefaultWriter()

	case Ofile:
		if err := openFile(c); err != nil {
			return err
		}
		logMgr.setDefaultWriter()

	case Osyslog:
		if err := openSyslog(c); err != nil {
			return err
		}
		logMgr.setSyslogWriter()

	case Onone:
		logMgr.Logger.SetOutput(ioutil.Discard)
		logMgr.Logger.SetFlags(0)

		logMgr.cl.SetOutput(ioutil.Discard)
		logMgr.cl.SetFlags(0)

		logMgr.level = Lfatal
		debugNone()
		return nil

	default:
		return fmt.Errorf("Unknown logging facility: %s", l)
	}

	C.vsw_log_verbose(C.bool(c.Verbose))

	// Check modules to debug
	logMgr.modulesToDebug = make(map[string]struct{})

	if len(c.Debugs) > 0 {
		for _, n := range c.Debugs {
			logMgr.modulesToDebug[n] = struct{}{}
		}

		if _, ok := logMgr.modulesToDebug["*"]; ok {
			// Enable debugging on all modules
			debugAll()
		} else {
			// Selectively enable/disable debugging
			for n, l := range logMgr.modules {
				if _, found := logMgr.modulesToDebug[n]; found {
					l.EnableDebug()
				} else {
					l.DisableDebug()
				}
			}
		}
	} else {
		// Disable all debug
		debugNone()
	}

	return nil
}

// Default Logger
func DefaultLogger() *Logger {
	return std
}

// New returns Logger.
// Name is used to enable or disable logging per module name.
// Name shall not contain '%'.
func New(name string) (*Logger, error) {
	if strings.Contains(name, "%") {
		return nil, errors.New("Name cannot contain '%'.")
	}

	logMgr.mutex.Lock()
	defer logMgr.mutex.Unlock()

	if _, exists := logMgr.modules[name]; exists {
		return nil, fmt.Errorf("Module '%v' already exists.", name)
	}

	// Allocate logger ID
	id := -1
	for index, l := range logMgr.ids {
		if l == nil {
			id = index
			break
		}
	}

	if id == -1 {
		return nil, errors.New("Limit for a number of modules exceeded.")
	}

	logger := &Logger{
		name:   name,
		prefix: "[" + name + "] ",
		id:     id,
		mgr:    logMgr,
	}

	logMgr.modules[name] = logger
	logMgr.ids[id] = logger

	logger.SetDebugLevel(logMgr.debug)

	// check if we should enable debugging on this module
	if _, found := logMgr.modulesToDebug[name]; logMgr.debugAll || found {
		logger.EnableDebug()
	} else {
		logger.DisableDebug()
	}

	return logger, nil
}

func (lm *logManager) delete(logger *Logger) {
	logMgr.mutex.Lock()
	defer logMgr.mutex.Unlock()

	logMgr.ids[logger.id] = nil
	delete(logMgr.modules, logger.name)
}

func (lm *logManager) setDefaultWriter() {
	lm.dbg = lm.defaultPrint
	lm.info = lm.defaultPrint
	lm.warning = lm.defaultPrint
	lm.err = lm.defaultPrint
}

func (lm *logManager) setSyslogWriter() {
	lm.dbg = lm.Writer.Debug
	lm.info = lm.Writer.Info
	lm.warning = lm.Writer.Warning
	lm.err = lm.Writer.Err
}

func (lm *logManager) defaultPrint(str string) error {
	lm.Print(str)
	return nil
}

// EnableDebugLog enables debug log for the module specified by name.
func EnableDebugLog(name string) {
	logMgr.mutex.Lock()
	defer logMgr.mutex.Unlock()

	if logger, ok := logMgr.modules[name]; ok {
		logMgr.modulesToDebug[name] = struct{}{}
		logger.EnableDebug()
	}
}

// DisableDebugLog disables debug log for the module specified by name.
func DisableDebugLog(name string) {
	logMgr.mutex.Lock()
	defer logMgr.mutex.Unlock()

	if logger, ok := logMgr.modules[name]; ok {
		delete(logMgr.modulesToDebug, name)
		logger.DisableDebug()
	}
}

// SetVerbose sets verbose mode of the logger.
// If verbose is enabled, filename and line number are added to the log.
func SetVerbose(verbose bool) {
	logMgr.mutex.Lock()
	C.vsw_log_verbose(C.bool(verbose))
	logMgr.mutex.Unlock()
}

// No locking
func debugAll() {
	logMgr.debugAll = true
	for _, logger := range logMgr.modules {
		logger.EnableDebug()
	}
}

// DebugAll enables debug log of all modules.
// Even debug log is enabled for all modules, debug logs for each module
// can be disabled indvidually with Logger.DisableDebug.
func DebugAll() {
	logMgr.mutex.Lock()
	defer logMgr.mutex.Unlock()

	debugAll()
}

// No locking
func debugNone() {
	logMgr.debugAll = false
	for _, logger := range logMgr.modules {
		logger.DisableDebug()
	}
}

// DebugNone disables debug log of all modules.
// Even debug log is disabled for all modules, debug logs for each module
// can be enabled indvidually with Logger.EnableDebug.
//
// If a module is added to the logger with New after
// logging is diabled with DisableAllLogger, then the logging for
// the module is disabled by default. If logging is required,
// it must be explicitly enabled.
func DebugNone() {
	logMgr.mutex.Lock()
	defer logMgr.mutex.Unlock()

	debugNone()
}

// LogLevel returns the current minimum logging level.
func LogLevel() Level {
	logMgr.mutex.Lock()
	defer logMgr.mutex.Unlock()

	return logMgr.level
}

// SetLogLevel sets the minimum level to log to the given level.
//
// When set to Lerror, for instance, it logs anything equal to or
// higher than Lerror, i.e. logs only Lfatal and Lerror level logs.
//
// When set to Ldebug, all logs are logged.
func SetLogLevel(level Level) {
	logMgr.mutex.Lock()
	defer logMgr.mutex.Unlock()

	logMgr.level = level
	C.vsw_log_set_level(C.vsw_log_level_t(level))
}

// DebugLevel returns the default debug level.
func DebugLevel() uint8 {
	logMgr.mutex.Lock()
	defer logMgr.mutex.Unlock()

	return logMgr.debug
}

// SetDebugLevel sets the default debug level to level.
// It overrides debug level of all modules.
//
// Debug level of each module can be overrid by Logger.SetDebugLevel.
func SetDebugLevel(level uint8) {
	logMgr.mutex.Lock()
	defer logMgr.mutex.Unlock()

	logMgr.debug = level

	for _, logger := range logMgr.modules {
		logger.debug = level
	}
}

// Name returns module name associated with the logger.
func (l *Logger) Name() string {
	return l.name
}

// ID returns unique ID associated with the logger.
func (l *Logger) ID() int {
	return l.id
}

// EnableDebug enables debug log.
func (l *Logger) EnableDebug() {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	l.debugEnabled = true
	C.vsw_log_debug_enable(C.int(l.id))
}

// DisableDebug disables debug log.
func (l *Logger) DisableDebug() {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	l.debugEnabled = false
	C.vsw_log_debug_disable(C.int(l.id))
}

// DebugEnabled returns if debug log is enabled or not.
func (l *Logger) DebugEnabled() bool {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	return l.debugEnabled
}

// DebugLevel returns the current debug level.
func (l *Logger) DebugLevel() uint8 {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	return l.debug
}

// SetDebugLevel sets the current debug level.
func (l *Logger) SetDebugLevel(level uint8) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	l.debug = level
	C.vsw_log_set_debug_level(C.uint32_t(l.id), C.uint8_t(level))
}

// Close closes the logger.
// Any call after Close is not guaranteed to be safe.
func (l *Logger) Close() {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	l.debugEnabled = false
	l.mgr.delete(l)
}

// Debug logs a message if enabled with SetLogLevel and
// debug is equal or smaller than the debug level
// specified by SetDebugLevel.
//
// If syslog is available, it logs with severity LOG_DEBUG,
// Otherwise, logs to file or stdout depedning on the setting.
// Arguments are handled in the manner of fmt.Printf.
func (l *Logger) Debug(debug uint8, format string, v ...interface{}) error {
	if !l.debugEnabled || debug > l.debug {
		return nil
	}
	return l.mgr.dbg(tagDebug + l.prefix + fmt.Sprintf(format, v...))
}

// Info logs a message if enabled in the setting.
// If syslog is available, it logs with severity LOG_INFO,
// Otherwise, logs to file or stdout depedning on the setting.
// Arguments are handled in the manner of fmt.Printf.
func (l *Logger) Info(format string, v ...interface{}) error {
	if l.mgr.level < Linfo {
		return nil
	}
	return l.mgr.info(tagInfo + l.prefix + fmt.Sprintf(format, v...))
}

// Warning logs a message if enabled in the setting.
// If syslog is available, it logs with severity LOG_WARNING,
// Otherwise, logs to file or stdout depedning on the setting.
// Arguments are handled in the manner of fmt.Printf.
func (l *Logger) Warning(format string, v ...interface{}) error {
	if l.mgr.level < Lwarning {
		return nil
	}
	return l.mgr.warning(tagWarning + l.prefix + fmt.Sprintf(format, v...))
}

// Err logs a message if enabled in the setting.
// If syslog is available, it logs with severity LOG_ERR,
// Otherwise, logs to file or stdout depedning on the setting.
// Arguments are handled in the manner of fmt.Printf.
func (l *Logger) Err(format string, v ...interface{}) error {
	if l.mgr.level < Lerror {
		return nil
	}
	return l.mgr.err(tagError + l.prefix + fmt.Sprintf(format, v...))
}

// Printf is equivalent to Printf of log.Logger.
// Outputs log if level is at least Linfo, and logging is enabled for the module.
func (l *Logger) Printf(format string, v ...interface{}) {
	if l.mgr.level < Linfo {
		return
	}
	l.mgr.Printf(tagInfo+l.prefix+format, v...)
}

// Fatalf is equivalent to Fatalf of log.Logger.
func (l *Logger) Fatalf(format string, v ...interface{}) {
	l.mgr.Fatalf(tagFatal+l.prefix+format, v...)
}

// Panicf is equivalent to Panicf of log.Panicf.
// It overrides any logging level.
func (l *Logger) Panicf(format string, v ...interface{}) {
	l.mgr.Panicf(l.prefix+format, v...)
}

type logType int

const (
	tFatal   = logType(C.t_fatal)
	tErr     = logType(C.t_err)
	tWarning = logType(C.t_warning)
	tInfo    = logType(C.t_info)
	tDebug   = logType(C.t_debug)
)

func (l logType) String() string {
	s := map[logType]string{
		tFatal:   "fatal",
		tErr:     "err",
		tWarning: "warning",
		tInfo:    "info",
		tDebug:   "debug",
	}
	return s[l]
}

type cLoggerMsg struct {
	time time.Time
	id   int
	lt   logType
	body string
}

func (cm cLoggerMsg) String() string {
	return fmt.Sprintf("%v ID=%d Type=%v Body='%s'", cm.time, cm.id, cm.lt, cm.body)
}

var cLoggerCh = make(chan cLoggerMsg, 100)

// Shall be started only once
func cLoggerRoutine() {
	var buf []byte
	var tags = map[logType]string{
		tFatal:   tagFatal,
		tErr:     tagError,
		tWarning: tagWarning,
		tInfo:    tagInfo,
		tDebug:   tagDebug,
	}

	for msg := range cLoggerCh {
		l := logMgr.ids[msg.id]

		buf = buf[:0]
		formatHeader(&buf, msg.time)
		buf = append(buf, tags[msg.lt]...)
		buf = append(buf, l.prefix...)
		buf = append(buf, msg.body...)
		s := *(*string)(unsafe.Pointer(&buf))

		if l.mgr.Writer != nil {
			switch msg.lt {
			case tFatal:
				logMgr.cl.Output(0, s)
			case tErr:
				logMgr.Err(s)
			case tWarning:
				logMgr.Warning(s)
			case tInfo:
				logMgr.Info(s)
			case tDebug:
				logMgr.Debug(s)
			}
		} else {
			logMgr.cl.Output(0, s)
		}

		if msg.lt == tFatal {
			os.Exit(1)
		}
	}
}

//export LoggerOutput
func LoggerOutput(cmsg *C.struct_logger_message) {
	cLoggerCh <- cLoggerMsg{
		time: time.Unix(int64(cmsg.ts.tv_sec), int64(cmsg.ts.tv_nsec)),
		id:   int(cmsg.id),
		lt:   logType(cmsg.lt),
		body: C.GoString(cmsg.body),
	}
}

//export LoggerGetID
func LoggerGetID(name *C.char) C.int {
	l, ok := logMgr.modules[C.GoString(name)]
	if !ok {
		// If we can't find the given module name,
		// then we return defaultLoggerID. This will
		// make logging with defaultLoggerName.
		return C.int(defaultLoggerID)
	}
	return C.int(l.id)
}

var std *Logger

func init() {
	logMgr.setDefaultWriter()

	// Prepare default logger for C modules
	logger, err := New(defaultLoggerName)
	if err != nil {
		panic("Can't create default logger")
	}

	if logger.id != defaultLoggerID {
		panic("Can't reserve default ID for default logger.")
	}

	std = logger

	go cLoggerRoutine()
}
