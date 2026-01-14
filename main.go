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

// --- CONFIGURACIÓN ---
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

// --- RATE LIMITER ---
type RequestTracker struct {
	lastAccess map[string]time.Time
	mu         sync.Mutex
}

var tracker = RequestTracker{lastAccess: make(map[string]time.Time)}

// --- PLANTILLA HTML (Responsive & Moderna) ---
var pageTmpl = template.Must(template.New("page").Parse(`
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <title>Cerbero-Go</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: system-ui, sans-serif; background: #f4f6f8; padding: 20px; color: #333; }
        .container { max-width: 800px; margin: auto; background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); }
        h1 { color: #0d6efd; border-bottom: 2px solid #eee; padding-bottom: 15px; margin-top: 0; }
        .upload-section { background: #e7f1ff; padding: 20px; border-radius: 8px; margin-bottom: 25px; border: 1px dashed #0d6efd; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th { text-align: left; padding: 12px; background: #f8f9fa; border-bottom: 2px solid #dee2e6; }
        td { padding: 12px; border-bottom: 1px solid #dee2e6; vertical-align: middle; }
        .btn { padding: 8px 16px; border-radius: 6px; text-decoration: none; cursor: pointer; border: none; font-weight: 600; display: inline-block; }
        .btn-dl { background: #0d6efd; color: white; }
        .btn-dl:hover { background: #0b5ed7; }
        .btn-del { background: #dc3545; color: white; margin-left: 5px; }
        .btn-del:hover { background: #bb2d3b; }
        input[type="password"] { padding: 8px; border: 1px solid #ced4da; border-radius: 4px; margin-right: 5px; }
        input[type="file"] { margin-bottom: 10px; display: block; width: 100%; }
        .meta { font-size: 0.85em; color: #6c757d; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Cerbero-Go <span style="font-size: 0.6em; color: #6c757d; font-weight: normal;">v1.1 Stable</span></h1>
        
        <div class="upload-section">
            <form method="POST" action="/upload" enctype="multipart/form-data">
                <label style="font-weight:bold; display:block; margin-bottom:5px;">Subir Archivo:</label>
                <input type="file" name="file" required>
                <div style="margin-top:10px;">
                    {{if .PasswordEnabled}}
                        <input type="password" name="password" placeholder="Contraseña de acceso">
                    {{end}}
                    <button type="submit" class="btn btn-dl">Iniciar Subida</button>
                </div>
            </form>
        </div>

        <table>
            <thead><tr><th>Archivo</th><th style="width:120px;">Acciones</th></tr></thead>
            <tbody>
                {{range .Files}}
                <tr>
                    <td>
                        <div style="font-weight:bold;">{{.Name}}</div>
                        <div class="meta">{{.HumanSize}} - {{.ModTime.Format "02/01/2006 15:04"}}</div>
                    </td>
                    <td>
                        <a href="/download/{{.RelPath}}" class="btn btn-dl">▼</a>
                        {{if $.EnableDelete}}
                        <form method="POST" action="/delete" style="display:inline;">
                            <input type="hidden" name="path" value="{{.RelPath}}">
                            {{if $.PasswordEnabled}}<input type="password" name="password" placeholder="Clave" style="width:60px; padding:6px;">{{end}}
                            <button type="submit" class="btn btn-del" onclick="return confirm('¿Eliminar {{.Name}}?')">🗑</button>
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

// --- FUNCIONES UTILITARIAS ---

func humanSize(n int64) string {
	sizes := []string{"B", "KB", "MB", "GB", "TB"}
	f, i := float64(n), 0
	for f >= 1024 && i < len(sizes)-1 {
		f /= 1024
		i++
	}
	return fmt.Sprintf("%.2f %s", f, sizes[i])
}

func isRateLimited(ip string) bool {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if last, exists := tracker.lastAccess[ip]; exists && time.Since(last) < 500*time.Millisecond {
		return true // Bloquea si hay más de 2 peticiones por segundo
	}
	tracker.lastAccess[ip] = time.Now()
	return false
}

func securePath(requestedPath string) (string, error) {
	absRoot, _ := filepath.Abs(rootDir)
	targetPath := filepath.Join(absRoot, filepath.Clean("/"+requestedPath))
	if !strings.HasPrefix(targetPath, absRoot) {
		return "", fmt.Errorf("acceso denegado: intento de path traversal")
	}
	return targetPath, nil
}

func checkPassword(r *http.Request) bool {
	if password == "" { return true }
	return subtle.ConstantTimeCompare([]byte(r.FormValue("password")), []byte(password)) == 1
}

// --- HANDLERS ---

func renderIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" { http.NotFound(w, r); return }
	
	entries, err := os.ReadDir(rootDir)
	if err != nil {
		http.Error(w, "Error leyendo el directorio raíz", 500)
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
	
	// Ordenar por fecha (más reciente primero)
	sort.Slice(files, func(i, j int) bool { return files[i].ModTime.After(files[j].ModTime) })

	pageTmpl.Execute(w, map[string]interface{}{
		"Files":           files,
		"EnableDelete":    enableDelete,
		"PasswordEnabled": password != "",
	})
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if isRateLimited(host) {
		http.Error(w, "Demasiadas peticiones (Rate Limit)", 429)
		return
	}

	// 1. Establecer límite estricto de lectura
	r.Body = http.MaxBytesReader(w, r.Body, int64(maxUploadMB)<<20)

	// 2. PARSEAR FORMULARIO (CRUCIAL: Esto descarga el archivo al temp antes de validar lógica)
	// Usamos 32MB de buffer en RAM, el resto va a disco temporal.
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		if strings.Contains(err.Error(), "request body too large") {
			http.Error(w, fmt.Sprintf("El archivo excede el límite de %d MB", maxUploadMB), 413)
		} else {
			http.Error(w, "Error al procesar la subida (¿Disco lleno o conexión cortada?)", 400)
		}
		return
	}

	// 3. Verificar contraseña AHORA (ya tenemos los campos del form seguros)
	if !checkPassword(r) {
		http.Error(w, "Contraseña incorrecta", 401)
		return
	}

	// 4. Recuperar el archivo procesado
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "No se seleccionó ningún archivo", 400)
		return
	}
	defer file.Close()

	// 5. Guardar en destino final
	dstPath, err := securePath(filepath.Base(header.Filename))
	if err != nil {
		http.Error(w, "Nombre de archivo inválido", 403)
		return
	}

	dst, err := os.Create(dstPath)
	if err != nil {
		log.Printf("Error creando archivo: %v", err)
		http.Error(w, "Error de escritura en el servidor", 500)
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		log.Printf("Error guardando datos: %v", err)
		http.Error(w, "Error durante el guardado", 500)
		return
	}

	log.Printf("[UPLOAD] %s subido exitosamente desde %s", header.Filename, host)
	http.Redirect(w, r, "/", 303)
}

func main() {
	// Definición de flags
	flag.StringVar(&listenAddr, "listen", ":8080", "Dirección IP y puerto (ej: :8080)")
	flag.StringVar(&rootDir, "root", "./archivos", "Carpeta donde se guardan los archivos")
	flag.IntVar(&maxUploadMB, "maxmb", 512, "Límite máximo de subida en MB")
	flag.StringVar(&password, "password", "", "Contraseña para proteger subidas/borrados")
	flag.BoolVar(&enableDelete, "delete", true, "Permitir borrar archivos (true/false)")
	flag.Parse()

	// Configuración de rutas
	absPath, err := filepath.Abs(rootDir)
	if err != nil {
		log.Fatal("Error resolviendo ruta raíz:", err)
	}
	rootDir = absPath

	if err := os.MkdirAll(rootDir, 0755); err != nil {
		log.Fatal("No se pudo crear el directorio raíz:", err)
	}

	// Routers
	http.HandleFunc("/", renderIndex)
	http.HandleFunc("/upload", uploadHandler)
	http.HandleFunc("/download/", func(w http.ResponseWriter, r *http.Request) {
		relPath := strings.TrimPrefix(r.URL.Path, "/download/")
		absPath, err := securePath(relPath)
		if err != nil {
			http.Error(w, "Acceso Prohibido", 403)
			return
		}
		http.ServeFile(w, r, absPath)
	})
	http.HandleFunc("/delete", func(w http.ResponseWriter, r *http.Request) {
		if !enableDelete {
			http.Error(w, "El borrado está deshabilitado", 403)
			return
		}
		if r.Method == "POST" && checkPassword(r) {
			path := r.FormValue("path")
			if target, err := securePath(path); err == nil {
				os.Remove(target)
				log.Printf("[DELETE] %s eliminado", filepath.Base(target))
			}
		}
		http.Redirect(w, r, "/", 303)
	})

	fmt.Println("------------------------------------------------------")
	fmt.Printf("  Cerbero-Go v1.1 iniciado correctamente\n")
	fmt.Printf(" Directorio: %s\n", rootDir)
	fmt.Printf(" Escuchando: http://localhost%s\n", listenAddr)
	if password != "" {
		fmt.Println(" Modo: PRIVADO (Requiere contraseña)")
	} else {
		fmt.Println("  Modo: PÚBLICO (Sin contraseña)")
	}
	fmt.Println("------------------------------------------------------")
	
	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		log.Fatal("Error al iniciar servidor:", err)
	}
}
