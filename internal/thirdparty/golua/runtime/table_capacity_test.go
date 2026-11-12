package runtime

import "testing"

func TestHashCapacity(t *testing.T) {
	for _, n := range []int{0, 1, 7, 32, 65} {
		table := NewTableWithHashCapacity(n)
		for i := 0; i < n+10; i++ {
			table.Set(StringValue(string(rune('a'+i))), IntValue(int64(i)))
		}
		for i := 0; i < n+10; i++ {
			if got := table.Get(StringValue(string(rune('a' + i)))); got != IntValue(int64(i)) {
				t.Fatalf("capacity %d entry %d: %v", n, i, got)
			}
		}
	}
}
