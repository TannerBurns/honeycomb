package models

import (
	"errors"
	"os"
)

type RegistryHive struct {
	Filepath string   `json:"filepath"`
	RootKey  *NodeKey `json:"root_key"`
	Ok       bool     `json:"parsed"`
	Error    []string `json:"errors"`
}

func NewRegistryHive(path string) (rh *RegistryHive, err error) {
	_, err = os.Stat(path)
	if os.IsNotExist(err) {
		err = errors.New("File does not exist")
		return
	}
	rh = &RegistryHive{Filepath: path}
	return
}

func (rh *RegistryHive) Parse() {
	rh.Ok = false
	fin, err := os.Open(rh.Filepath)
	if err != nil {
		err = errors.New("Failed to open file: " + rh.Filepath)
		rh.Error = append(rh.Error, err.Error())
		return
	}
	magic := make([]byte, 4)
	_, err = fin.Read(magic)
	if err != nil {
		err = errors.New("Failed to read first 4 bytes, cannot verify hive file")
		rh.Error = append(rh.Error, err.Error())
		return
	}
	if magic[0] != 'r' || magic[1] != 'e' || magic[2] != 'g' || magic[3] != 'f' {
		err = errors.New("Magic header is not 'regf', cannot verify hive file")
		rh.Error = append(rh.Error, err.Error())
		return
	}
	_, err = fin.Seek(4132, 0)
	if err != nil {
		rh.Error = append(rh.Error, err.Error())
		return
	}
	rh.RootKey, err = NewNodeKey(fin)
	if err != nil {
		rh.Error = append(rh.Error, err.Error())
		return
	}
	rh.Ok = true
	fin.Close()
	return
}
