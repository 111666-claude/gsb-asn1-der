// Package asn1der 解析 DER 的 TLV。
package asn1der

import (
	"errors"
	"fmt"
)

// Counter 记录比较次数。
type Counter struct {
	Scanned int
}

// Node 是一个 TLV 元素。
type Node struct {
	Class       int
	Constructed bool
	Tag         int
	Value       []byte
	Children    []*Node
	Path        string
	Int         int64
}

// Doc 是解析结果。
type Doc struct {
	Roots []*Node
}

func parseOne(data []byte, pos int, prefix string, c *Counter) (*Node, int, error) {
	if pos >= len(data) {
		return nil, pos, errors.New("eof")
	}
	c.Scanned++
	first := data[pos]
	node := &Node{Class: int(first >> 6), Constructed: first&0x20 != 0, Tag: int(first & 0x1f)}
	i := pos + 1
	if i >= len(data) {
		return nil, pos, errors.New("eof")
	}
	length := int(data[i])
	i++
	if i+length > len(data) {
		return nil, pos, errors.New("eof")
	}
	node.Value = append([]byte(nil), data[i:i+length]...)
	node.Path = prefix + fmt.Sprintf("%d", node.Tag)
	if len(node.Value) > 0 {
		node.Int = int64(node.Value[0])
		for _, b := range node.Value[1:] {
			node.Int = node.Int<<8 | int64(b)
		}
	}
	return node, i + length, nil
}

// Parse 解析全部元素。
func Parse(data []byte, c *Counter) (*Doc, error) {
	doc := &Doc{}
	pos := 0
	for pos < len(data) {
		node, next, err := parseOne(data, pos, "", c)
		if err != nil {
			break
		}
		doc.Roots = append(doc.Roots, node)
		pos = next
	}
	return doc, nil
}

// Find 按路径找元素。
func (d *Doc) Find(path string, c *Counter) *Node {
	for _, node := range d.Roots {
		c.Scanned++
		if node.Path == path {
			return node
		}
	}
	return nil
}
