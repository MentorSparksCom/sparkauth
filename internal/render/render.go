package render

import (
	"html/template"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type Renderer struct {
	templates map[string]*template.Template
	funcMap   template.FuncMap
}

func New() *Renderer {
	return &Renderer{
		templates: make(map[string]*template.Template),
		funcMap: template.FuncMap{
			"safeHTML": func(s string) template.HTML {
				return template.HTML(s)
			},
			"lower": strings.ToLower,
			"upper": strings.ToUpper,
			"formatTime": func(t time.Time) string {
				return t.Format("Jan 2, 2006 15:04")
			},
			"formatDate": func(t time.Time) string {
				return t.Format("Jan 2, 2006")
			},
		},
	}
}

func (r *Renderer) Add(name string, files ...string) {
	t := template.Must(
		template.New(filepath.Base(files[0])).Funcs(r.funcMap).ParseFiles(files...),
	)
	r.templates[name] = t
}

func (r *Renderer) Render(c *gin.Context, code int, name string, data gin.H) {
	t, ok := r.templates[name]
	if !ok {
		log.Printf("Template %q not found", name)
		c.String(http.StatusInternalServerError, "Template not found: %s", name)
		return
	}
	c.Status(code)
	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(c.Writer, "layout", data); err != nil {
		log.Printf("Template render error for %q: %v", name, err)
	}
}
