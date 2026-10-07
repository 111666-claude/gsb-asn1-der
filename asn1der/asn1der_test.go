package asn1der

import "testing"

func TestParseShortLength(t *testing.T) {
	doc, err := Parse(TLV(0x04, []byte{1, 2, 3}), &Counter{})
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if len(doc.Roots) != 1 || len(doc.Roots[0].Value) != 3 {
		t.Fatalf("元素不对：%+v", doc.Roots)
	}
}

func TestTagStored(t *testing.T) {
	doc, _ := Parse(TLV(0x04, []byte{1}), &Counter{})
	if doc.Roots[0].Tag != 4 {
		t.Fatalf("标签号应是 4：%d", doc.Roots[0].Tag)
	}
}

func TestClassStored(t *testing.T) {
	doc, _ := Parse(TLV(0x02, []byte{1}), &Counter{})
	if doc.Roots[0].Class != 0 {
		t.Fatalf("类别应是 0：%d", doc.Roots[0].Class)
	}
}

func TestFindMissing(t *testing.T) {
	doc, _ := Parse(TLV(0x04, []byte{1}), &Counter{})
	if doc.Find("99", &Counter{}) != nil {
		t.Fatal("缺失路径应返回 nil")
	}
}

func TestEmptyData(t *testing.T) {
	doc, _ := Parse(nil, &Counter{})
	if len(doc.Roots) != 0 {
		t.Fatalf("空输入应无元素：%d", len(doc.Roots))
	}
}

func TestCounterCounts(t *testing.T) {
	c := &Counter{}
	Parse(TLV(0x04, []byte{1}), c)
	if c.Scanned == 0 {
		t.Fatal("应统计比较次数")
	}
}
