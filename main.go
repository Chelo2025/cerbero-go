package main

import (
	"crypto/subtle"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	listenAddr   string
	rootDir      string
	maxUploadMB  int
	password     string
	enableDelete bool
)

type FileInfo struct {
	Name, RelPath, HumanSize string
	Size                     int64
	ModTime                  time.Time
}

type RequestTracker struct {
	lastAccess map[string]time.Time
	mu         sync.Mutex
}

var tracker = RequestTracker{lastAccess: make(map[string]time.Time)}

var pageTmpl = template.Must(template.New("page").Parse(`
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <title>Cerbero-Go</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: system-ui, sans-serif; background: #f0f2f5; padding: 20px; color: #333; }
        .container { max-width: 800px; margin: auto; background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1 { color: #1a73e8; border-bottom: 2px solid #eee; padding-bottom: 10px; }
        .upload-section { background: #e8f0fe; padding: 15px; border-radius: 8px; margin-bottom: 20px; border: 1px dashed #1a73e8; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #ddd; }
        .btn { padding: 8px 14px; border-radius: 6px; text-decoration: none; cursor: pointer; border: none; font-weight: bold; }
        .btn-dl { background: #1a73e8; color: white; }
        .btn-del { background: #d93025; color: white; }
        input[type="password"], input[type="file"] { padding: 8px; border: 1px solid #ccc; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Cerbero-Go <small style="font-size: 14px; color: #666;">v1.1 Stable</small></h1>
        <div class="upload-section">
            <form method="POST" action="/upload" enctype="multipart/form-data">
                <input type="file" name="file" required>
                {{if .PasswordEnabled}}<input type="password" name="password" placeholder="Contraseña">{{end}}
                <button type="submit" class="btn btn-dl">Subir</button>
            </form>
        </div>
        <table>
            <thead><tr><th>Nombre</th><th>Tamaño</th><th>Acciones</th></tr></thead>
            <tbody>
                {{range .Files}}
                <tr>
                    <td><strong>{{.Name}}</strong></td>
                    <td>{{.HumanSize}}</td>
                    <td>
                        <a href="/download/{{.RelPath}}" class="btn btn-dl">Descargar</a>
                        {{if $.EnableDelete}}
                        <form method="POST" action="/delete" style="display:inline;">
                            <input type="hidden" name="path" value="{{.RelPath}}">
                            {{if $.PasswordEnabled}}<input type="password" name="password" placeholder="Clave" style="width:60px;">{{end}}
                            <button type="submit" class="btn btn-del" onclick="return confirm('¿Eliminar?')">X</button>
                        </form>
                        {{end}}
                    </td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>
</body>
</html>`))

func humanSize(n int64) string {
	sizes := []string{"B", "KB", "MB", "GB"}
	f, i := float64(n), 0
	for f >= 1024 && i < len(sizes)-1 { f /= 1024; i++ }
	return fmt.Sprintf("%.1f %s", f, sizes[i])
}

func isRateLimited(ip string) bool {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if last, exists := tracker.lastAccess[ip]; exists && time.Since(last) < 1*time.Second { return true }
	tracker.lastAccess[ip] = time.Now()
	return false
}

func securePath(requestedPath string) (string, error) {
	absRoot, _ := filepath.Abs(rootDir)
	targetPath := filepath.Join(absRoot, filepath.Clean("/"+requestedPath))
	if !strings.HasPrefix(targetPath, absRoot) { return "", fmt.Errorf("denied") }
	return targetPath, nil
}

func checkPassword(r *http.Request) bool {
	if password == "" { return true }
	return subtle.ConstantTimeCompare([]byte(r.FormValue("password")), []byte(password)) == 1
}

func renderIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" { http.NotFound(w, r); return }
	entries, _ := os.ReadDir(rootDir)
	var files []FileInfo
	for _, entry := range entries {
		if entry.IsDir() { continue }
		info, _ := entry.Info()
		files = append(files, FileInfo{Name: entry.Name(), Size: info.Size(), RelPath: entry.Name(), HumanSize: humanSize(info.Size()), ModTime: info.ModTime()})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].ModTime.After(files[j].ModTime) })
	pageTmpl.Execute(w, map[string]interface{}{"Files": files, "EnableDelete": enableDelete, "PasswordEnabled": password != ""})
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if isRateLimited(host) { http.Error(w, "Rate limit", 429); return }
	r.Body = http.MaxBytesReader(w, r.Body, int64(maxUploadMB)<<20)
	if err := r.ParseMultipartForm(int64(maxUploadMB) << 20); err != nil {
		http.Error(w, "Error de archivo/tamaño", 400)
		return
	}
	if !checkPassword(r) { http.Error(w, "Clave incorrecta", 401); return }
	file, header, err := r.FormFile("file")
	if err != nil { http.Error(w, "No archivo", 400); return }
	defer file.Close()
	dstPath, _ := securePath(filepath.Base(header.Filename))
	dst, err := os.Create(dstPath)
	if err != nil { http.Error(w, "Error disco", 500); return }
	defer dst.Close()
	io.Copy(dst, file)
	http.Redirect(w, r, "/", 303)
}

func main() {
	flag.StringVar(&listenAddr, "listen", ":8080", "Puerto")
	flag.StringVar(&rootDir, "root", "./archivos", "Carpeta")
	flag.IntVar(&maxUploadMB, "maxmb", 512, "Límite MB")
	flag.StringVar(&password, "password", "", "Clave")
	flag.BoolVar(&enableDelete, "delete", true, "Borrado")
	flag.Parse()
	abs, _ := filepath.Abs(rootDir)
	rootDir = abs
	os.MkdirAll(rootDir, 0755)
	http.HandleFunc("/", renderIndex)
	http.HandleFunc("/upload", uploadHandler)
	http.HandleFunc("/download/", func(w http.ResponseWriter, r *http.Request) {
		abs, err := securePath(strings.TrimPrefix(r.URL.Path, "/download/"))
		if err != nil { http.Error(w, "Forbidden", 403); return }
		http.ServeFile(w, r, abs)
	})
	http.HandleFunc("/delete", func(w http.ResponseWriter, r *http.Request) {
		if enableDelete && checkPassword(r) {
			if path, err := securePath(r.FormValue("path")); err == nil { os.Remove(path) }
		}
		http.Redirect(w, r, "/", 303)
	})
	log.Printf("Cerbero-Go escuchando en %s. Carpeta: %s", listenAddr, rootDir)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}
