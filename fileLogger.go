package main

import (
	"log"
	"os"
)

type fileLogger struct {
	*log.Logger
	logPath string
	logFile **os.File
}

func (l fileLogger) println(v ...interface{}) {
	if _, err := os.Stat(l.logPath); err != nil {
		if os.IsNotExist(err) {
			logFile, err := os.OpenFile(l.logPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
			if err != nil {
				log.Fatalln("--> global -/", err)
			}
			l.SetOutput(logFile)
			l.logFile = &logFile
		} else {
			log.Fatalln("--> global -/", err)
		}
	}
	l.Println(v...)
}

func (l fileLogger) close() {
	(*l.logFile).Close()
}
