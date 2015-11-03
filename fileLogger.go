package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

// fileLogger represents a logger that logs to a file
type fileLogger struct {
	// pointer to internal logger
	*log.Logger

	// whether or not to log to stderr
	stderr bool
}

func newFileLogger(stderrPrefix, stdErrLogging bool, logPath string) *fileLogger {
	l = &fileLogger{stderr: stdErrLogging}
	if stderrPrefix == false {
		log.SetFlags(0)
		log.SetPrefix("")
	} else {
		log.SetPrefix("TunneLS: ")
	}
	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		<-sigs
		l.fatalf("%s terminating", globalPrefix)
	}()
	if logPath != "" {
		logFile, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			log.Fatal(err)
		}
		l.Logger = log.New(logFile, "cserver: ", 3)
	}
	return l
}

// first checks to make sure file exists
// then prints arguments to logger as fmt.Print
func (l *fileLogger) print(v ...interface{}) {
	if l.Logger != nil {
		l.Print(v...)
	}
	if l.stderr == true {
		log.Print(v...)
	}
}

// first checks to make sure file exists
// then prints arguments to logger as fmt.Printf
func (l fileLogger) printf(format string, v ...interface{}) {
	if l.Logger != nil {
		l.Printf(format, v...)
	}
	if l.stderr == true {
		log.Printf(format, v...)
	}
}

// first checks to make sure file exists
// then prints arguments to logger as fmt.Println
func (l *fileLogger) println(v ...interface{}) {
	if l.Logger != nil {
		l.Println(v...)
	}
	if l.stderr == true {
		log.Println(v...)
	}
}

// fatal is equal to l.print followed by a call to os.Exit(1)
func (l *fileLogger) fatal(v ...interface{}) {
	l.print(v...)
	os.Exit(1)
}

// fatalf is equal to l.printf followed by a call to os.Exit(1)
func (l *fileLogger) fatalf(format string, v ...interface{}) {
	l.printf(format, v...)
	os.Exit(1)
}

// fatalln is equal to l.Println followed by a call to os.Exit(1)
func (l *fileLogger) fatalln(v ...interface{}) {
	l.println(v...)
	os.Exit(1)
}

// panic is equal to l.print followed by a call to panic
func (l *fileLogger) panic(v ...interface{}) {
	s := fmt.Sprint(v...)
	l.print(s)
	panic(s)
}

// panicf is equal to l.printf followed by a call to panic
func (l *fileLogger) panicf(format string, v ...interface{}) {
	s := fmt.Sprintf(format, v...)
	l.printf(s)
	panic(s)
}

// panicln is equal to l.println followed by a call to panic
func (l *fileLogger) panicln(v ...interface{}) {
	s := fmt.Sprintln(v...)
	l.println(s)
	panic(s)
}
