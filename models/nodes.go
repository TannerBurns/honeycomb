package models

import (
	"encoding/binary"
	"errors"
	"os"
	"time"
)

type NodeKey struct {
	ChildNodes []*NodeKey `json:"child_nodes"`
	//ChildValues       []ValueKey `json:"child_values"`
	Timestamp         time.Time `json:"timestamp"`
	SubkeysCount      uint32    `json:"subkeys_count"`
	ParentOffset      uint32    `json:"parent_offset"`
	LFRecordOffset    uint32    `json:"lfrecord_offset"`
	ClassnameOffset   uint32    `json:"classname_offset"`
	SecurityKeyOffset uint32    `json:"securitykey_offset"`
	ValuesCount       uint32    `json:"values_count"`
	ValuesListOffset  uint32    `json:"valueslist_offset"`
	NameLength        uint16    `json:"name_length"`
	IsRootKey         bool      `json:"isrootkey"`
	ClassnameLength   uint16    `json:"classname_length"`
	Name              string    `json:"name"`
	ClassnameData     []byte    `json:"classname_data"`
	ParentNodeKey     *NodeKey  `json:"parentnode_key"`
}

func (nk *NodeKey) ReadNodeStructure(hive *os.File, ts time.Time) (err error) {
	tbuff := make([]byte, 2)
	fbuff := make([]byte, 4)
	nk.Timestamp = ts
	_, err = hive.Read(fbuff)
	if err != nil {
		return
	}
	if fbuff[0] != 0x6e || fbuff[1] != 0x6b {
		err = errors.New("Invalid nodekey fbuff, cannot read")
		return
	}
	startingOffset, err := hive.Seek(0, 1)
	if err != nil {
		return
	}
	if fbuff[2] == 0x2c {
		nk.IsRootKey = true
	} else {
		nk.IsRootKey = false
	}
	_, err = hive.Seek(4, 1)
	if err != nil {
		return
	}
	_, err = hive.Read(fbuff)
	if err != nil {
		return
	}
	nk.ParentOffset = binary.LittleEndian.Uint32(fbuff)
	_, err = hive.Read(fbuff)
	if err != nil {
		return
	}
	nk.SubkeysCount = binary.LittleEndian.Uint32(fbuff)
	_, err = hive.Seek(4, 1)
	if err != nil {
		return
	}
	_, err = hive.Read(fbuff)
	if err != nil {
		return
	}
	nk.LFRecordOffset = binary.LittleEndian.Uint32(fbuff)
	_, err = hive.Seek(4, 1)
	if err != nil {
		return
	}
	_, err = hive.Read(fbuff)
	if err != nil {
		return
	}
	nk.ValuesCount = binary.LittleEndian.Uint32(fbuff)
	_, err = hive.Read(fbuff)
	if err != nil {
		return
	}
	nk.ValuesListOffset = binary.LittleEndian.Uint32(fbuff)
	_, err = hive.Read(fbuff)
	if err != nil {
		return
	}
	nk.SecurityKeyOffset = binary.LittleEndian.Uint32(fbuff)
	_, err = hive.Read(fbuff)
	if err != nil {
		return
	}
	nk.ClassnameOffset = binary.LittleEndian.Uint32(fbuff)
	_, err = hive.Seek(startingOffset+68, 0)
	if err != nil {
		return
	}
	_, err = hive.Read(tbuff)
	if err != nil {
		return
	}
	nk.NameLength = binary.LittleEndian.Uint16(tbuff)
	_, err = hive.Read(tbuff)
	if err != nil {
		return
	}
	nk.ClassnameLength = binary.LittleEndian.Uint16(tbuff)

	buf := make([]byte, nk.NameLength)
	_, err = hive.Read(buf)
	if err != nil {
		return
	}
	nk.Name = string(buf)
	_, err = hive.Seek(int64(nk.ClassnameOffset)+4100, 0)
	return
}
