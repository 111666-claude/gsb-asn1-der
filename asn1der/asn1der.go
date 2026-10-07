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
	node := &Node{Class: int(first >> 6), Constructed: first&0x20 != 0, Tag: int(first & 0x1f)}
	i := pos + 1

	if node.Tag == 0x1f {
		tag := 0
		for {
			if i >= len(data) {
				return nil, pos, errors.New("eof：标签号不完整")
			}
			b := data[i]
			i++
			tag = tag<<7 | int(b&0x7f)
			if b&0x80 == 0 {
				break
			}
		}
		node.Tag = tag
	}

	if i >= len(data) {
		return nil, pos, errors.New("eof：缺长度字节")
	}
	lb := data[i]
	i++
	var length int
	switch {
	case lb < 0x80:
		length = int(lb)
	case lb == 0x80:
		return nil, pos, errors.New("DER 不允许不定长")
	default:
		n := int(lb & 0x7f)
		if n == 0 || i+n > len(data) {
			return nil, pos, errors.New("eof：长度不完整")
		}
		for j := 0; j < n; j++ {
			length = length<<8 | int(data[i+j])
		}
		i += n
	}

	if i+length > len(data) || i+length < i {
		return nil, pos, errors.New("eof：内容超出数据范围")
	}
	end := i + length
	node.Value = append([]byte(nil), data[i:end]...)
	node.Path = prefix + fmt.Sprintf("%d", node.Tag)

	if len(node.Value) > 0 {
		n := int64(0)
		if node.Value[0]&0x80 != 0 {
			n = -1
		}
		for _, b := range node.Value {
			n = n<<8 | int64(b)
		}
		node.Int = n
	}

	if node.Constructed {
		for i < end {
			child, next, err := parseOne(data, i, node.Path+".", c)
			if err != nil {
				return nil, pos, err
			}
			if next > end {
				return nil, pos, errors.New("子元素超出父元素范围")
			}
			node.Children = append(node.Children, child)
			i = next
		}
		if i != end {
			return nil, pos, errors.New("子元素未占满父元素内容")
		}
	}

	return node, end, nil
}

// Parse 解析全部元素。
func Parse(data []byte, c *Counter) (*Doc, error) {
	doc := &Doc{index: map[string]*Node{}}
	if c == nil {
		c = &Counter{}
	}
	pos := 0
	for pos < len(data) {
		node, next, err := parseOne(data, pos, "", c)
		if err != nil {
			return doc, err
		}
		doc.Roots = append(doc.Roots, node)
		doc.index[node.Path] = node
		pos = next
	}
	return doc, nil
}

// Find 按路径走索引找元素。
func (d *Doc) Find(path string, c *Counter) *Node {
	if c != nil {
		c.Scanned++
	}
	return d.index[path]
}
