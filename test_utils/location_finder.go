package test_utils

import (
	"os"
	"path/filepath"
	"runtime"
)

func GetProjectRootPath() (string, error) {
	return getProjectRootPathForStack()
}

func getProjectRootPathForStack() (string, error) {
	_, filename, _, _ := runtime.Caller(0)

	runningUnderYegai := "reflect" == filepath.Base(filepath.Dir(filename))
	if !runningUnderYegai {
		if _, err := os.Stat(filename); err == nil {
			// remove ../location_finder.go from the path
			// fmt.Printf("filename=%s\n", filename)
			projectRootPath := filepath.Dir(filepath.Dir(filename))
			return projectRootPath, nil
		}
	} else {
		goPath := os.Getenv("GOPATH")
		goPathLocationOfProject := filepath.Join(goPath, "src/github.com/taliesins/traefik-plugin-oidc/test_utils/location_finder.go")
		// fmt.Printf("goPathLocationOfProject=%s\n", goPathLocationOfProject)
		if _, err := os.Stat(goPathLocationOfProject); err == nil {
			// remove ../location_finder.go from the path
			projectRootPath := filepath.Dir(filepath.Dir(goPathLocationOfProject))
			return projectRootPath, nil
		}

	}

	// We are running the tests using yeagi so fix the path by getting it relative to the GOPATH
	currentDirectory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	// fmt.Printf("using default cwd=%s\n", currentDirectory)
	return currentDirectory, nil
}
