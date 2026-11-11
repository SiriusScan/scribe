package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFactsBatch(t *testing.T) {
	body := `{"args":["--dialect","sirius"],"facts":[{"host":"localhost","port":80,"protocol":"tcp","state":"open","service":"http","product":"fixture","version":"1"},{"host":"localhost","port":81}],"scripts":[{"id":"a","source":"return {api_version=1,rule=function(t) return t.product=='fixture' and t.version=='1' end,action=function(t) return {verdict='not_vulnerable',data=t.service} end}"},{"id":"b","source":"return {api_version=1,action=function() return {} end}"}]}`
	w := httptest.NewRecorder()
	runHandler().ServeHTTP(w, httptest.NewRequest("POST", "/run", strings.NewReader(body)))
	if w.Code != 200 || len(strings.Split(strings.TrimSpace(w.Body.String()), "\n")) != 4 || !strings.Contains(w.Body.String(), `"verdict":"not_vulnerable"`) || !strings.Contains(w.Body.String(), `"status":"skipped"`) {
		t.Fatal(w.Code, w.Body.String())
	}
}
