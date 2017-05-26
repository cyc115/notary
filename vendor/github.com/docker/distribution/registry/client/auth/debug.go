package auth

import "github.com/Sirupsen/logrus"

func PrettyPrintMap(header string, m map[string]string) {
	logrus.Debug("--->> %v", header)
	for k, v := range m {
		logrus.Debug("------>> %v : %v", k, v)
	}
	logrus.Debug("--->> end of %v", header)
}

func PrettyPrintList(header string, l ...[]string) {
	logrus.Debug("--->> %v", header)
	for k, v := range l {
		logrus.Debug("------>> %v : %v", k, v)
	}
	logrus.Debug("--->> end of %v", header)
}
