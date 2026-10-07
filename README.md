# asn1-der

解析 DER 的 TLV：长度两种形态、构造位递归、整数补码、长标签号，以及按路径查找。只用标准库。

```
go test ./...
go vet ./...
go run ./cmd/asn1der --sample=longlen
go run ./cmd/asn1der --sample=nested
go run ./cmd/asn1der --sample=negint
go run ./cmd/asn1der --sample=hightag
go run ./cmd/asn1der --sample=work
```

## 口径

- **标签**：首字节高两位是类别、次高位是构造位、低五位是标签号；低五位为 `1F` 时后续字节每字节低 7 位续接标签号。
- **长度**：首字节小于 `0x80` 是短形态；否则低 7 位是后续长度字节数，拼成大端整数。
- **构造位**：置位的值是容器，要在自己的长度范围内递归解析子元素。
- **整数**：内容是补码大端，最高位为 1 表示负数。
- **路径**：从根开始把标签号用点号连起来；`Find(path)` 走索引。

## 不变量

- 元素的内容长度严格等于声明长度。
- 构造元素的所有子元素都落在自己的长度范围内。
- `scanned` 不随元素数乘查询次数放大：八百个元素查八百次的 `scanned` 不超过 6000。

## 输出契约

`Node` 含类别、构造位、标签号、内容、子元素与整数解码值。场景打印一行 JSON。
`--sample=work` 打印 `{"nodes": N, "scanned": N}`。
