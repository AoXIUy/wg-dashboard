package main

import (
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestEmbeddedAssets(t *testing.T) {
	if len(indexHtml) == 0 {
		t.Fatal("embedded indexHtml is empty")
	}

	subFS, err := fs.Sub(staticFS, "static")
	if err != nil {
		t.Fatalf("fs.Sub static failed: %v", err)
	}

	f, err := subFS.Open("css/leaflet.css")
	if err != nil {
		t.Fatalf("failed to open embedded css/leaflet.css: %v", err)
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil || len(content) == 0 {
		t.Fatalf("failed to read embedded css/leaflet.css or empty: %v", err)
	}
}

func TestGeoIP_GracefulDegradation(t *testing.T) {
	// 指定不存在的 mmdb 路径
	GeoCityPath = filepath.Join(SandboxDataDir, "non_existent_city.mmdb")
	GeoASNPath = filepath.Join(SandboxDataDir, "non_existent_asn.mmdb")
	_ = os.Remove(GeoCityPath)
	_ = os.Remove(GeoASNPath)

	initGeoIP()

	if ipProvider == nil {
		t.Fatal("ipProvider should not be nil; should gracefully degrade to fallback provider")
	}

	// 测试私有 IP 短路
	info, err := ipProvider.GetInfo([]byte{10, 0, 0, 1})
	if err != nil {
		t.Fatalf("GetInfo for private IP failed: %v", err)
	}
	if info.Source != "private" {
		t.Errorf("expected source 'private', got '%s'", info.Source)
	}
}

func TestServer_EmbeddedStaticHTTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	subFS, err := fs.Sub(staticFS, "static")
	if err != nil {
		t.Fatalf("fs.Sub failed: %v", err)
	}
	r.StaticFS("/static", http.FS(subFS))
	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, indexHtml)
	})

	// 测试 GET /
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	if w.Body.Len() == 0 {
		t.Errorf("expected body, got empty")
	}

	// 测试 GET /static/css/leaflet.css
	reqStatic := httptest.NewRequest("GET", "/static/css/leaflet.css", nil)
	wStatic := httptest.NewRecorder()
	r.ServeHTTP(wStatic, reqStatic)

	if wStatic.Code != http.StatusOK {
		t.Errorf("expected status 200 for static file, got %d", wStatic.Code)
	}
}
