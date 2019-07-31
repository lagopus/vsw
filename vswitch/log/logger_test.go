//
// Copyright 2019 Nippon Telegraph and Telephone Corporation.
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

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	syslogFile  = "/var/log/syslog"
	testModule  = "test%d"
	testMessage = "test message [%d]"
)

var msgCounter = 0
var moduleCounter = 0
var badTime = time.Time{}

func newTestMessage() string {
	msgCounter++
	return fmt.Sprintf(testMessage, msgCounter)
}

func newTestModule() string {
	moduleCounter++
	return fmt.Sprintf(testModule, moduleCounter)
}

func createExpectedMessage(logger *Logger, msg string) string {
	return fmt.Sprintf("[%s] %s", logger.Name(), msg)
}

// checkMessage checks whether received matches to expected.
// Received is in the form of the following:
//
//	2018/09/04 09:40:27 [test] Dummy test message
//
// Means that the first two words are date and time. We ignore
// date and time, and matches the rest of the message with
// expected.
//
// Returns time.Time found in the received message.
func checkMessage(t *testing.T, expected, received string) time.Time {
	// Split received message as follows:
	//   r[0]: Date
	//   r[1]: Time
	//   r[2]: Message body
	r := strings.SplitN(received, " ", 3)

	// check date and time
	tm, err := time.Parse("2006/01/02 15:04:05.000000", r[0]+" "+r[1])
	if err != nil {
		t.Errorf("Date/Time parse error: %v", err)
		return time.Time{}
	}

	r[2] = strings.Trim(r[2], "\n")
	t.Logf("read: Expected \"%v\"; Got \"%v\"", expected, r[2])

	if r[2] != expected {
		t.Errorf("NG")
		return time.Time{}
	}

	t.Logf("OK")
	return tm
}

func createLoggerWithName(t *testing.T, name string) *Logger {
	logger, err := New(name)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Logf("New logger for '%s' created.", logger.Name())
	return logger
}

func createLogger(t *testing.T) *Logger {
	return createLoggerWithName(t, newTestModule())
}

func initLogger(t *testing.T, c *LogConfig) {
	err := Init(c)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
}

func initLogAndCreateLogger(t *testing.T, c *LogConfig) *Logger {
	initLogger(t, c)
	return createLogger(t)
}

func TestLoggingBeforeInit(t *testing.T) {
	t.Logf("Override logManager.Logger with test output.")
	buf := &strings.Builder{}
	logMgr.Logger = log.New(buf, "", DefaultLogFlag)

	logger := createLogger(t)

	t.Logf("Sending log message.")
	msg := newTestMessage()
	logger.Printf(msg)

	checkMessage(t, createExpectedMessage(logger, msg), buf.String())

	t.Logf("closing logger")
	logger.Close()

	t.Logf("done")
}

func TestInitStdout(t *testing.T) {
	t.Logf("Override os.Stdout with test output.")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	oldStdout := os.Stdout
	os.Stdout = w

	defer func() {
		os.Stdout = oldStdout
		r.Close()
		w.Close()
	}()

	config := LogConfig{Ostdout, "", "", "lagopus", "", "", false, "debug", []string{}}
	t.Logf("Initializing logger with: %v\n", config)

	logger := initLogAndCreateLogger(t, &config)

	t.Logf("Sending log message.")
	msg := newTestMessage()
	logger.Printf(msg)

	// read a line
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		t.Fatalf("Can't read line: %v", scanner.Err())
	}
	readMessage := scanner.Text()

	checkMessage(t, createExpectedMessage(logger, msg), readMessage)

	t.Logf("closing logger")
	logger.Close()

	t.Logf("done")
}

func TestInitFile(t *testing.T) {
	fileName := fmt.Sprintf("%s/vsw_logger_test.%d", os.TempDir(), os.Getpid())
	t.Logf("Generated log filename: %v", fileName)

	// Make sure the file doesn't exist
	os.Remove(fileName)

	// Remove file when this test is done
	defer func() {
		t.Logf("Removing logfile '%s'", fileName)
		os.Remove(fileName)
	}()

	config := LogConfig{Ofile, "", "", "", "", fileName, false, "debug", []string{}}
	t.Logf("Initializing logger with: %v\n", config)

	logger := initLogAndCreateLogger(t, &config)

	t.Logf("Sending log message.")
	msg1 := newTestMessage()
	logger.Printf(msg1)

	// check if we can open and read
	r, err := os.Open(fileName)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// read a line
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		t.Fatalf("Can't read line: %v", scanner.Err())
	}
	readMessage := scanner.Text()

	t1 := checkMessage(t, createExpectedMessage(logger, msg1), readMessage)
	if t1 == badTime {
		t.Fatalf("Log is corrupted.")
	}

	t.Logf("Closing logger and log file.")
	logger.Close()
	r.Close()

	t.Logf("Wait for a second.")
	time.Sleep(1 * time.Second)

	t.Logf("Now we reopen the log file.")

	logger = initLogAndCreateLogger(t, &config)

	t.Logf("Sending log message again.")
	msg2 := newTestMessage()
	logger.Printf(msg2)

	// reopen
	r, err = os.Open(fileName)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// read lines
	scanner = bufio.NewScanner(r)

	// 1st line
	if !scanner.Scan() {
		t.Fatalf("Can't read line: %v", scanner.Err())
	}
	if line := scanner.Text(); line != readMessage {
		t.Fatalf("Log file is corrupted; read '%v', expected '%v'", line, readMessage)
	}
	t.Logf("First log message matched. Ok.")

	// 2nd line
	if !scanner.Scan() {
		t.Fatalf("Can't read line: %v", scanner.Err())
	}
	readMessage2 := scanner.Text()

	t2 := checkMessage(t, createExpectedMessage(logger, msg2), readMessage2)
	if t2 == badTime {
		t.Fatalf("Log is corrupted.")
	}

	if diff := t2.Unix() - t1.Unix(); diff > 0 {
		t.Logf("Time diff between two logs is more than a second; %d second: OK", diff)
	} else {
		t.Errorf("Log should be at least 1 second a part; %d second(s) different", diff)
	}

	t.Logf("Closing logger and log file.")
	logger.Close()
	r.Close()

	t.Logf("done")
}

func TestInitSyslog(t *testing.T) {
	config := LogConfig{Osyslog, "", "", "lagopus", DefaultFacility, "", false, "debug", []string{}}
	t.Logf("Initializing logger with: %v\n", config)

	logger := initLogAndCreateLogger(t, &config)

	t.Logf("Sending log message and wait for 100 msec.")
	msg := newTestMessage()
	logger.Printf(msg)
	time.Sleep(100 * time.Millisecond)

	// Check if log is sent to syslog
	t.Logf("Scan %s to see the log is sent", syslogFile)
	r, err := os.Open(syslogFile)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	pid := strconv.Itoa(os.Getpid())
	re := regexp.MustCompile(`^([a-zA-Z]+) +([0-9]+) +([0-9:]+) +([a-zA-Z\-]+) ([a-z]+)\[([0-9]+)\]: (.*)`)
	expMsg := createExpectedMessage(logger, msg)
	matchFound := false

	scanner := bufio.NewScanner(r)
	for !matchFound && scanner.Scan() {
		if m := re.FindStringSubmatch(scanner.Text()); m != nil {
			if m[6] == pid && checkMessage(t, expMsg, m[7]) != badTime {
				t.Logf("Found expcted log: %v", m[0])
				matchFound = true
			}
		}
	}

	if !matchFound {
		t.Errorf("Expected log not found.")
	}

	t.Logf("Closing logger and syslog.")
	logger.Close()
	r.Close()
}

func testDebugEnabler(t *testing.T, loggers []*Logger, r io.Reader, result []bool) {
	var expected []string

	for i := 0; i < len(loggers); i++ {
		msg := newTestMessage()
		loggers[i].Debug(0, msg)
		if result[i] {
			expected = append(expected, createExpectedMessage(loggers[i], msg))
		}
	}

	// check if expected messages are found
	scanner := bufio.NewScanner(r)

	if len(expected) > 0 {
		for _, msg := range expected {
			if !scanner.Scan() {
				t.Fatalf("No log; '%s' was expected.", msg)
			}
			checkMessage(t, msg, scanner.Text())
		}

		// check if there's any unexpected messages found
		if scanner.Scan() {
			t.Fatalf("Unexpected log found: %s", scanner.Text())
		}

		t.Logf("Found all expected output.")
	} else {
		if scanner.Scan() {
			t.Fatalf("Unexpected log found: %s", scanner.Text())
		}
		t.Logf("No output found as expected.")
	}

}

func TestLogDebugEnabler(t *testing.T) {
	fileName := fmt.Sprintf("%s/vsw_logger_test.%d", os.TempDir(), os.Getpid())
	t.Logf("Generated log filename: %v", fileName)

	// Make sure the file doesn't exist
	os.Remove(fileName)

	// Remove file when this test is done
	defer func() {
		t.Logf("Removing logfile '%s'", fileName)
		os.Remove(fileName)
	}()

	config := LogConfig{Ofile, "", "", "", "", fileName, false, "debug", []string{}}
	t.Logf("Initializing logger with: %v\n", config)

	initLogger(t, &config)

	// Create loggers
	loggers := make([]*Logger, 3)
	var err error
	for i := 0; i < len(loggers); i++ {
		loggers[i], err = New(newTestModule()) // disabled
		if err != nil {
			t.Fatalf("Can't create logger: %v", err)
		}
	}

	// Open log file
	r, err := os.Open(fileName)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	//
	// Test Cases
	//				0	1	2
	// -----------------------------------------------
	// 0. default			-	-	-
	// 1. DebugAll()		x	x	x
	// 2. DebugNone()	 	-	-	-
	// 3. EnableDebug(0)		x	-	-
	// 4. DisableDebug(1)		x	-	-
	// 5. EnableDebug(1)		x	x	-
	// 6. DisableDebug(0)		-	x	-
	// 7. DisableDebug(1)		-	-	-
	// 8. EnableDebugLog(2)		-	-	x
	// 9. DisableDebugLog(2)	-	-	-
	// 10.DebugAll()		x	x	x
	//
	// We should see outputs from logger marked with 'x'.
	//
	type tests struct {
		name    string
		prepare func([]*Logger)
		result  []bool
	}
	testCases := []tests{
		{
			"default",
			func(_ []*Logger) {},
			[]bool{false, false, false},
		},
		{
			"DebugAll()",
			func(_ []*Logger) { DebugAll() },
			[]bool{true, true, true},
		},
		{
			"DebugNone()",
			func(_ []*Logger) { DebugNone() },
			[]bool{false, false, false},
		},
		{
			"logger[0].EnableDebug()",
			func(l []*Logger) { l[0].EnableDebug() },
			[]bool{true, false, false},
		},
		{
			"logger[1].DisableDebug()",
			func(l []*Logger) { l[1].DisableDebug() },
			[]bool{true, false, false},
		},
		{
			"logger[1].EnableDebug()",
			func(l []*Logger) { l[1].EnableDebug() },
			[]bool{true, true, false},
		},
		{
			"logger[0].DisableDebug()",
			func(l []*Logger) { l[0].DisableDebug() },
			[]bool{false, true, false},
		},
		{
			"logger[1].DisableDebug()",
			func(l []*Logger) { l[1].DisableDebug() },
			[]bool{false, false, false},
		},
		{
			"EnableDebugLog(logger[2])",
			func(l []*Logger) { EnableDebugLog(l[2].Name()) },
			[]bool{false, false, true},
		},
		{
			"DisableDebugLog(logger[2])",
			func(l []*Logger) { DisableDebugLog(l[2].Name()) },
			[]bool{false, false, false},
		},
		{
			"DebugAll()",
			func(l []*Logger) { DebugAll() },
			[]bool{true, true, true},
		},
	}

	for _, test := range testCases {
		t.Logf("testing - %v", test.name)
		test.prepare(loggers)

		for i, logger := range loggers {
			if logger.DebugEnabled() != test.result[i] {
				t.Fatalf("logger[%d].Enabled() doesn't match; expected %v, got %v",
					i, test.result[i], logger.DebugEnabled())
			}
		}

		testDebugEnabler(t, loggers, r, test.result)
	}

	t.Logf("Passed all test cases")

	// tear down
	for _, logger := range loggers {
		logger.Close()
	}
	r.Close()

	// Make sure all logger is reneabled again
	DebugAll()
}

func TestDuplicatedLogger(t *testing.T) {
	config := LogConfig{Ostdout, "", "", "lagopus", "", "", false, "debug", []string{}}
	t.Logf("Initializing logger with: %v\n", config)

	logger := initLogAndCreateLogger(t, &config)

	t.Logf("Creating logger with duplicated name: %s", logger.Name())

	if logger2, err := New(logger.Name()); err == nil {
		t.Fatalf("Duplicated logger created!")
		logger2.Close()
	} else if logger2 != nil {
		t.Logf("Logger != nil; although error is returned: %v", err)
	} else {
		t.Logf("Duplicated log wasn't created: %v", err)
	}

	t.Logf("closing logger")
	logger.Close()
	t.Logf("done")
}

func TestLoggerCAPI(t *testing.T) {
	fileName := fmt.Sprintf("%s/vsw_logger_test.%d", os.TempDir(), os.Getpid())
	t.Logf("Generated log filename: %v", fileName)

	// Make sure the file doesn't exist
	os.Remove(fileName)

	// Remove file when this test is done
	defer func() {
		t.Logf("Removing logfile '%s'", fileName)
	}()

	config := LogConfig{Ofile, "", "", "", "", fileName, false, "info", []string{"*"}}
	t.Logf("Initializing logger with: %v\n", config)

	initLogger(t, &config)

	// Open log file
	r, err := os.Open(fileName)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	t.Logf("Sending log message via C API.")
	msg := newTestMessage()
	vsw_printf(msg)

	time.Sleep(time.Millisecond)

	scanner := bufio.NewScanner(r)

	if !scanner.Scan() {
		t.Fatalf("Can't read line: %v", scanner.Err())
	}
	readMessage := scanner.Text()

	checkMessage(t, createExpectedMessage(std, msg), readMessage)

	t.Logf("> %v", readMessage)

	// Create logger
	logger := createLogger(t)
	SetVerbose(true)

	t.Logf("Test vsw_log_getid()")
	id := vsw_log_getid(logger.name)
	if id != logger.ID() {
		t.Fatalf("Logger ID didn't match: %d != %d", id, logger.ID())
	}
	t.Logf("Ok. ID=%d\n", id)

	t.Logf("Testing vsw_msg_* API")
	vsw_log_debug(id, 0, "debug msg")
	vsw_log_emit(id, tInfo, "info msg")
	vsw_log_emit(id, tWarning, "warning msg")
	vsw_log_emit(id, tErr, "error msg")
	//	vsw_log_emit(id, tFatal, "fatal msg")

	time.Sleep(time.Millisecond)

	for scanner.Scan() {
		t.Logf("> %v", scanner.Text())
	}

	r.Close()
	logger.Close()

	t.Logf("done")
}
