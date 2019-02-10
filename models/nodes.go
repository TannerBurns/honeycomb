package models

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
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

func NewNodeKey(hive *os.File) (*NodeKey, error) {
	nk := &NodeKey{}
	err := nk.ReadNodeStructure(hive)
	if err != nil {
		return nk, err
	}
	err = nk.ReadChildNodes(hive)
	if err != nil {
		return nk, err
	}
	return nk, nil
}

func (nk *NodeKey) ReadNodeStructure(hive *os.File) (err error) {
	tbuf := make([]byte, 2)
	fbuf := make([]byte, 4)
	info, err := hive.Stat()
	if err != nil {
		return
	}
	nk.Timestamp = info.ModTime()
	_, err = hive.Read(fbuf)
	if err != nil {
		return
	}
	if fbuf[0] != 0x6e || fbuf[1] != 0x6b {
		err = errors.New("Invalid nodekey fbuf, cannot read")
		return
	}
	startingOffset, err := hive.Seek(0, 1)
	if err != nil {
		return
	}
	if fbuf[2] == 0x2c {
		nk.IsRootKey = true
	} else {
		nk.IsRootKey = false
	}
	_, err = hive.Seek(4, 1)
	if err != nil {
		return
	}
	_, err = hive.Read(fbuf)
	if err != nil {
		return
	}
	nk.ParentOffset = binary.LittleEndian.Uint32(fbuf)
	_, err = hive.Read(fbuf)
	if err != nil {
		return
	}
	nk.SubkeysCount = binary.LittleEndian.Uint32(fbuf)
	_, err = hive.Seek(4, 1)
	if err != nil {
		return
	}
	_, err = hive.Read(fbuf)
	if err != nil {
		return
	}
	nk.LFRecordOffset = binary.LittleEndian.Uint32(fbuf)
	_, err = hive.Seek(4, 1)
	if err != nil {
		return
	}
	_, err = hive.Read(fbuf)
	if err != nil {
		return
	}
	nk.ValuesCount = binary.LittleEndian.Uint32(fbuf)
	_, err = hive.Read(fbuf)
	if err != nil {
		return
	}
	nk.ValuesListOffset = binary.LittleEndian.Uint32(fbuf)
	_, err = hive.Read(fbuf)
	if err != nil {
		return
	}
	nk.SecurityKeyOffset = binary.LittleEndian.Uint32(fbuf)
	_, err = hive.Read(fbuf)
	if err != nil {
		return
	}
	nk.ClassnameOffset = binary.LittleEndian.Uint32(fbuf)
	_, err = hive.Seek(startingOffset+68, 0)
	if err != nil {
		return
	}
	_, err = hive.Read(tbuf)
	if err != nil {
		return
	}
	nk.NameLength = binary.LittleEndian.Uint16(tbuf)
	_, err = hive.Read(tbuf)
	if err != nil {
		return
	}
	nk.ClassnameLength = binary.LittleEndian.Uint16(tbuf)

	buf := make([]byte, nk.NameLength)
	_, err = hive.Read(buf)
	if err != nil {
		return
	}
	nk.Name = string(buf)
	_, err = hive.Seek(int64(nk.ClassnameOffset)+4100, 0)
	if err != nil {
		return
	}
	nbuf := make([]byte, nk.ClassnameLength)
	_, err = hive.Read(nbuf)
	if err != nil {
		return
	}
	nk.ClassnameData = nbuf
	return
}

func (nk *NodeKey) ReadChildNodes(hive *os.File) (err error) {
	if int(nk.LFRecordOffset) != -1 {
		_, err = hive.Seek(4096+int64(nk.LFRecordOffset)+4, 0)
		if err != nil {
			return
		}
		buf := make([]byte, 2)
		_, err = hive.Read(buf)
		if err != nil {
			return
		}
		if buf[0] == 0x72 && buf[1] == 0x69 {
			_, err = hive.Read(buf)
			if err != nil {
				return
			}
			count := binary.LittleEndian.Uint16(buf)
			for i := uint16(0); i < count; i++ {
				pos, err := hive.Seek(0, 1)
				if err != nil {
					return err
				}
				buf2 := make([]byte, 4)
				_, err = hive.Read(buf2)
				if err != nil {
					return err
				}
				offset := binary.LittleEndian.Uint32(buf2)
				_, err = hive.Seek(4096+int64(offset)+4, 0)
				if err != nil {
					return err
				}
				_, err = hive.Read(buf)
				if err != nil {
					return err
				}
				if !(buf[0] == 0x6c && (buf[1] == 0x66 || buf[1] == 0x68)) {
					cur, err := hive.Seek(0, 1)
					if err != nil {
						return err
					}
					sc := strconv.FormatInt(cur, 10)
					err = errors.New("Bad LF/LH record at: " + sc)
					return err
				}
				err = nk.ParseChildNodes(hive)
				if err != nil {
					return err
				}
				_, err = hive.Seek(pos+4, 0)
				if err != nil {
					return err
				}
			}
		} else if buf[0] == 0x6c && (buf[1] == 0x66 || buf[1] == 0x68) {
			err = nk.ParseChildNodes(hive)
			if err != nil {
				return
			}
		} else {
			cur, err := hive.Seek(0, 1)
			if err != nil {
				return err
			}
			sc := strconv.FormatInt(cur, 10)
			err = errors.New("Bad LF/LH/RI record at: " + sc)
			return err
		}
	}
	return
}

func (nk *NodeKey) ParseChildNodes(hive *os.File) (err error) {
	tbuf := make([]byte, 2)
	fbuf := make([]byte, 4)
	_, err = hive.Read(tbuf)
	if err != nil {
		return
	}
	count := binary.LittleEndian.Uint16(tbuf)
	topOfList, err := hive.Seek(0, 1)
	if err != nil {
		return
	}
	for i := 0; i < int(count); i++ {
		_, err = hive.Seek(topOfList+int64((i*8)), 0)
		if err != nil {
			return err
		}
		_, err = hive.Read(fbuf)
		if err != nil {
			return err
		}
		newoffset := binary.LittleEndian.Uint32(fbuf)
		_, err = hive.Seek(4, 1)
		if err != nil {
			return err
		}
		_, err = hive.Seek(4100+int64(newoffset), 0)
		if err != nil {
			return err
		}
		newnode, err := NewNodeKey(hive)
		if err != nil {
			return err
		}
		d, err := json.MarshalIndent(newnode, "", "    ")
		if err != nil {
			return err
		}
		fmt.Println(string(d))
		nk.ChildNodes = append(nk.ChildNodes, newnode)
	}
	_, err = hive.Seek(topOfList+int64((count*8)), 0)
	return
}
