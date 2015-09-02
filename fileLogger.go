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

func (l fileLogger) checkIfExist(){
	if _, err := os.Stat(l.logPath); err != nil {
		if os.IsNotExist(err) {
			logFile, err := os.OpenFile(l.logPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
			if err != nil {
				log.Fatalln("--> global -/", err)
			}
			l.SetOutput(logFile)
			*l.logFile = logFile
		} else {
			log.Fatalln("--> global -/", err)
		}
	}
}

func (l fileLogger) println(v ...interface{}) {
	l.checkIfExist()
	l.Println(v...)
}

func (l fileLogger) printf(format string, v ...interface{}) {
	l.checkIfExist()
	l.Printf(format, v...)
}

func (l fileLogger) close() {
	(*l.logFile).Close()
}
