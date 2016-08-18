package goutil

import (
	"os"
	"path/filepath"
	"github.com/mgutz/ansi"
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

//
func RemoveIllegalPathCharacters(path string) string {
	re, _ := regexp.Compile("[\\:*?\"<>|]")
	var buffer bytes.Buffer
	for _, c := range path {
		if re.MatchString(string(c))  == false {
			buffer.WriteRune(c)
		}
	}

	temp := buffer.String()
	temp = strings.Replace(temp, "/", "_", -1)

	// Remove the first underscore as there will be one after the port
	if len(temp) > 0 {
		if string(temp[0:1]) == "_" {
			temp = temp[1:]
		}
	}

	// Remove the last underscore as not necessary for the output file
	if len(temp) > 0 {
		if string(temp[len(temp) - 1:]) == "_" {
			temp = temp[0:len(temp) - 1]
		}
	}

	return temp
}

// Ensure that the user supplied path exists as a directory
func DoesDirectoryExist(path string) (bool) {
	file_info, err := os.Stat(path)
	if err == nil {
		if file_info.IsDir() == false {
			fmt.Println(ansi.Color("The item is not a directory", "red"))
			return false
		}

		return true
	} else {
		fmt.Println(ansi.Color(err.Error(), "red"))
	}

	if os.IsNotExist(err) { return false}
	return false
}

//
func IsPathDirectory(path string) (bool, error) {
	// Determine if the 'input' parameter is a file or directory
	f, err := os.Open(path)
	defer f.Close()
	if err != nil {
		return false, err
	}
	fi, err := f.Stat()
	if err != nil {
		return false, err
	}

	if fi.Mode().IsDir() == true {
		return true, nil
	}

	return false, nil
}

func GetApplicationDirectory() string {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		return ""
	}

	return dir
}

//
func RemoveDriveLetter(data string) string {
	match, _ := regexp.MatchString("^\\w:\\\\", data)
	if match == true {
		return data[3:]
	}

	return data
}

//
func GetFileNameWithoutExtension(file string) string {
	return strings.TrimSuffix(filepath.Base(file), filepath.Ext(filepath.Base(file)))
}

// Extract the file name and dir name from the full path
func SplitPath(filePath string) (fileName string, fileDirectory string) {

	lastIndex := strings.LastIndex(filePath, "\\")
	if lastIndex > -1 {
		fileName = filePath[lastIndex + 1:len(filePath)]
		fileDirectory = filePath[:lastIndex]
	}

	return fileName, fileDirectory
}
