package asn1der

// Scenario 是一个固定场景。
type Scenario struct {
	Name string
	Run  func() map[string]any
}

// TLV 拼一个元素。
func TLV(tag int, value []byte) []byte {
	out := []byte{byte(tag)}
	n := len(value)
	if n < 0x80 {
		out = append(out, byte(n))
	} else {
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, value...)
}

// Byte 取一个元素的标签号。
func Byte(tag int, value []byte) []byte {
	return TLV(tag, value)
}

// Samples 返回全部场景。
func Samples() []Scenario {
	return []Scenario{
		{Name: "longlen", Run: func() map[string]any {
			data := TLV(0x04, make([]byte, 200))
			doc, _ := Parse(data, &Counter{})
			if len(doc.Roots) == 0 {
				return map[string]any{"len": 0}
			}
			return map[string]any{"len": len(doc.Roots[0].Value)}
		}},
		{Name: "nested", Run: func() map[string]any {
			inner := append(TLV(0x02, []byte{1}), TLV(0x02, []byte{2})...)
			data := TLV(0x30, inner)
			doc, _ := Parse(data, &Counter{})
			if len(doc.Roots) == 0 {
				return map[string]any{"children": 0}
			}
			return map[string]any{"children": len(doc.Roots[0].Children)}
		}},
		{Name: "negint", Run: func() map[string]any {
			data := TLV(0x02, []byte{0xff})
			doc, _ := Parse(data, &Counter{})
			if len(doc.Roots) == 0 {
				return map[string]any{"int": 0}
			}
			return map[string]any{"int": doc.Roots[0].Int}
		}},
		{Name: "hightag", Run: func() map[string]any {
			data := []byte{0x9f, 0x20, 0x01, 0x00}
			doc, _ := Parse(data, &Counter{})
			if len(doc.Roots) == 0 {
				return map[string]any{"tag": 0}
			}
			return map[string]any{"tag": doc.Roots[0].Tag}
		}},
	}
}

// Work 跑规模线场景。
func Work(n int) map[string]any {
	var data []byte
	for i := 0; i < n; i++ {
		data = append(data, TLV(0x02, []byte{byte(i)})...)
	}
	doc, _ := Parse(data, &Counter{})
	c := &Counter{}
	for i := 0; i < n; i++ {
		doc.Find("999", c)
	}
	return map[string]any{"nodes": n, "scanned": c.Scanned}
}
