# Cerbero-Go v1.0

## Descripción
Cerbero-Go es un servidor HTTP escrito en **Go**, con interfaz web integrada, que permite **subir, descargar y borrar archivos** de manera segura.  
Está diseñado para ser **ligero, reproducible y seguro**, ideal para homelabs, entornos de pruebas y despliegues rápidos.

---

## Características principales
- **Compartir archivos** desde una carpeta configurable.  
-  **Protección opcional por contraseña** para subir y borrar.  
-  **Borrado seguro** de archivos (habilitable/deshabilitable).  
-  **Rate limiting por IP** para evitar abusos.  
-  **Límite de tamaño configurable** por subida.  
-  **Interfaz web integrada** con HTML/CSS embebido.  
-  **Configuración mediante parámetros** al ejecutar el binario.  

---

## Parámetros disponibles
- `-root`: Carpeta a compartir (ejemplo: `./archivos`)  
- `-listen`: Puerto y dirección (ejemplo: `:8080`)  
- `-password`: Clave de acceso web  
- `-delete`: Permite borrar archivos (`true/false`)  
- `-maxmb`: Límite de tamaño por subida  

---

## Instalación en Debian 13

```bash
# 1. Instalar Go y herramientas necesarias
su -c "apt update && apt upgrade"
su -c "apt install golang git -y"

# 2. Clonar el repositorio
git clone https://github.com/Chelo2025/Cerbero-Go
cd Cerbero-Go

# 3. Compilar el proyecto
go build -o cerbero-go main.go

# 4. Ejecutar con parámetros personalizados
./cerbero-go -root ./archivos -listen :8080 -password "miclave"

## Prueba de funcionamiento

Abrir el navegador en http://localhost:8080

Subir un archivo desde la interfaz web.

Descargarlo o borrarlo según permisos configurados.

## Autor

Marcelo Martinez - Chelo2025

🎓 Estudiante de Licenciatura en Tecnologías Digitales

🛡️ Técnico Superior en Redes Informáticas

🎓 Estudiante en Diplomado en Administración de Redes Linux con Orientación en Ciberseguridad y Ethical Hacking con Kali Linux
