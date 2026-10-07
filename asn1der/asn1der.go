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
	index map[string]*Node
}

func parseOne(data []byte, pos int, prefix string, c *Counter) (*Node, int, error) {
	if pos >= len(data) {
		return nil, pos, errors.New("eof")
	}
	c.Scanned++
	first := data[pos]
	node := &Node{Class: int(first >> 6), Constructed: first&0x20 != 0}
	i := pos + 1
	tag := int(first & 0x1f)
	if tag == 0x1f {
		tag = 0
		for {
			if i >= len(data) {
				return nil, pos, errors.New("eof")
			}
			c.Scanned++
			b := data[i]
			i++
			tag = tag<<7 | int(b&0x7f)
			if b&0x80 == 0 {
				break
			}
		}
	}
	node.Tag = tag
	if i >= len(data) {
		return nil, pos, errors.New("eof")
	}
	c.Scanned++
	lb := data[i]
	i++
	var length int
	if lb < 0x80 {
		length = int(lb)
	} else {
		n := int(lb & 0x7f)
		if n == 0 || n > 8 || i+n > len(data) {
			return nil, pos, errors.New("bad length")
		}
		for j := 0; j < n; j++ {
			length = length<<8 | int(data[i+j])
		}
		i += n
	}
	if i+length > len(data) {
		return nil, pos, errors.New("eof")
	}
	node.Value = append([]byte(nil), data[i:i+length]...)
	node.Path = prefix + fmt.Sprintf("%d", node.Tag)
	if len(node.Value) > 0 {
		node.Int = int64(int8(node.Value[0]))
		for _, b := range node.Value[1:] {
			node.Int = node.Int<<8 | int64(b)
		}
	}
	end := i + length
	if node.Constructed {
		childPrefix := node.Path + "."
		cpos := i
		for cpos < end {
			child, next, err := parseOne(data, cpos, childPrefix, c)
			if err != nil {
				return nil, pos, err
			}
			if next > end {
				return nil, pos, errors.New("child out of range")
			}
			node.Children = append(node.Children, child)
			cpos = next
		}
	}
	return node, end, nil
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
	doc.index = make(map[string]*Node)
	var add func(n *Node)
	add = func(n *Node) {
		if _, ok := doc.index[n.Path]; !ok {
			doc.index[n.Path] = n
		}
		for _, child := range n.Children {
			add(child)
		}
	}
	for _, node := range doc.Roots {
		add(node)
	}
	return doc, nil
}

// Find 按路径找元素。
func (d *Doc) Find(path string, c *Counter) *Node {
	c.Scanned++
	return d.index[path]
}
