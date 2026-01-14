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

// --- CONFIGURACIÓN Y SEGURIDAD ---
var (
	listenAddr   string
	rootDir      string
	maxUploadMB  int
	password     string
	enableDelete bool
)

type FileInfo struct {
	Name      string
	Size      int64
	ModTime   time.Time
	RelPath   string
	HumanSize string
}

type RequestTracker struct {
	lastAccess map[string]time.Time
	mu         sync.Mutex
}

var tracker = RequestTracker{lastAccess: make(map[string]time.Time)}

// Plantilla HTML integrada
var pageTmpl = template.Must(template.New("page").Parse(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Cerbero-Go</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: sans-serif; background: #f0f2f5; padding: 20px; }
        .container { max-width: 800px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #1a73e8; border-bottom: 2px solid #eee; padding-bottom: 10px; }
        .upload-section { background: #e8f0fe; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #ddd; }
        .btn { padding: 6px 12px; border-radius: 4px; text-decoration: none; cursor: pointer; border: none; }
        .btn-dl { background: #1a73e8; color: white; }
        .btn-del { background: #d93025; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Cerbero-Go <small style="font-size: 12px; color: #666;">v1.0</small></h1>
        <div class="upload-section">
            <form method="POST" action="/upload" enctype="multipart/form-data">
                <input type="file" name="file" required>
                {{if .PasswordEnabled}}<input type="password" name="password" placeholder="Contraseña">{{end}}
                <button type="submit" class="btn btn-dl">Subir Archivo</button>
            </form>
        </div>
        <table>
            <thead><tr><th>Nombre</th><th>Tamaño</th><th>Acciones</th></tr></thead>
            <tbody>
                {{range .Files}}
                <tr>
                    <td>{{.Name}}</td>
                    <td>{{.HumanSize}}</td>
                    <td>
                        <a href="/download/{{.RelPath}}" class="btn btn-dl">Descargar</a>
                        {{if $.EnableDelete}}
                        <form method="POST" action="/delete" style="display:inline;">
                            <input type="hidden" name="path" value="{{.RelPath}}">
                            {{if $.PasswordEnabled}}<input type="password" name="password" placeholder="Clave" style="width:60px;">{{end}}
                            <button type="submit" class="btn btn-del">X</button>
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

// --- FUNCIONES DE APOYO ---

func humanSize(n int64) string {
	sizes := []string{"B", "KB", "MB", "GB"}
	f := float64(n)
	i := 0
	for f >= 1024 && i < len(sizes)-1 {
		f /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", f, sizes[i])
}

func isRateLimited(ip string) bool {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	last, exists := tracker.lastAccess[ip]
	if exists && time.Since(last) < 1*time.Second {
		return true
	}
	tracker.lastAccess[ip] = time.Now()
	return false
}

func securePath(requestedPath string) (string, error) {
	absRoot, _ := filepath.Abs(rootDir)
	targetPath := filepath.Join(absRoot, filepath.Clean("/"+requestedPath))
	if !strings.HasPrefix(targetPath, absRoot) {
		return "", fmt.Errorf("acceso denegado")
	}
	return targetPath, nil
}

func checkPassword(r *http.Request) bool {
	if password == "" { return true }
	sent := r.FormValue("password")
	return subtle.ConstantTimeCompare([]byte(sent), []byte(password)) == 1
}

// --- HANDLERS ---

func renderIndex(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(rootDir)
	if err != nil {
		http.Error(w, "Error leyendo carpeta", 500)
		return
	}

	var files []FileInfo
	for _, entry := range entries {
		if entry.IsDir() { continue }
		info, _ := entry.Info()
		files = append(files, FileInfo{
			Name:      entry.Name(),
			Size:      info.Size(),
			RelPath:   entry.Name(),
			HumanSize: humanSize(info.Size()),
			ModTime:   info.ModTime(),
		})
	}

	sort.Slice(files, func(i, j int) bool { return files[i].ModTime.After(files[j].ModTime) })

	data := map[string]interface{}{
		"Files":           files,
		"EnableDelete":    enableDelete,
		"PasswordEnabled": password != "",
	}
	pageTmpl.Execute(w, data)
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if isRateLimited(host) { http.Error(w, "Límite excedido", 429); return }
	if r.Method != "POST" { http.Error(w, "Error", 405); return }
	if !checkPassword(r) { http.Error(w, "Clave errónea", 401); return }

	r.Body = http.MaxBytesReader(w, r.Body, int64(maxUploadMB)<<20)
	file, header, err := r.FormFile("file")
	if err != nil { http.Error(w, "Error", 400); return }
	defer file.Close()

	dstPath, _ := securePath(filepath.Base(header.Filename))
	dst, _ := os.Create(dstPath)
	defer dst.Close()
	io.Copy(dst, file)
	http.Redirect(w, r, "/", 303)
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(r.URL.Path, "/download/")
	abs, err := securePath(rel)
	if err != nil { http.Error(w, "Denegado", 403); return }
	http.ServeFile(w, r, abs)
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	if !enableDelete { return }
	if !checkPassword(r) { http.Error(w, "Clave errónea", 401); return }
	path, err := securePath(r.FormValue("path"))
	if err == nil { os.Remove(path) }
	http.Redirect(w, r, "/", 303)
}

func main() {
	flag.StringVar(&listenAddr, "listen", ":8080", "Puerto")
	flag.StringVar(&rootDir, "root", "./shared", "Carpeta")
	flag.IntVar(&maxUploadMB, "maxmb", 512, "Límite")
	flag.StringVar(&password, "password", "", "Clave")
	flag.BoolVar(&enableDelete, "delete", true, "Borrado")
	flag.Parse()

	abs, _ := filepath.Abs(rootDir)
	rootDir = abs
	os.MkdirAll(rootDir, 0755)

	http.HandleFunc("/", renderIndex)
	http.HandleFunc("/upload", uploadHandler)
	http.HandleFunc("/download/", downloadHandler)
	http.HandleFunc("/delete", deleteHandler)

	log.Printf("Cerbero-Go en puerto %s protegiendo %s", listenAddr, rootDir)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}
