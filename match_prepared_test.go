package scribe

import (
	"sync"
	"testing"
)

func TestPreparedBannerSelection(t *testing.T) {
	idx, err := NewIndex([]Script{{ID: "banner", Dialect: Sirius, Source: []byte("-- scribe: {\"match\":{\"all_of\":[{\"banner_regex\":\"^SSH-\"}],\"any_of\":[{\"banner_regex\":\"OpenSSH\"},{\"banner_regex\":\"Dropbear\"}]}}\nreturn {}")}})
	if err != nil {
		t.Fatal(err)
	}
	m := idx.entries[0].hints.Match
	if m.AllOf[0].bannerPattern == nil || m.AnyOf[0].bannerPattern == nil {
		t.Fatal("nested expressions not prepared")
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				for _, banner := range []string{"SSH-2.0-OpenSSH", "SSH-2.0-Dropbear", "HTTP OpenSSH", "SSH-2.0-other"} {
					want := banner == "SSH-2.0-OpenSSH" || banner == "SSH-2.0-Dropbear"
					got, identified := m.evaluate(Target{Banner: banner})
					if got != want || identified {
						t.Errorf("%q: match=%v identified=%v", banner, got, identified)
					}
				}
			}
		}()
	}
	wg.Wait()
	// Public Match values remain usable without an index and tolerate edits.
	direct := Match{BannerRegex: "["}
	if ok, _ := direct.evaluate(Target{Banner: "x"}); ok {
		t.Fatal("invalid regex accepted")
	}
	direct.BannerRegex = "x"
	if ok, _ := direct.evaluate(Target{Banner: "x"}); !ok {
		t.Fatal("direct match failed")
	}
}
