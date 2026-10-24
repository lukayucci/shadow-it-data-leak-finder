# Shadow IT & Data Leak Finder - Web SaaS

## Estructura Backend Creada

```
web/
├── app/
│   ├── core/           # Config, DB, Security
│   ├── models/         # User, Report (SQLAlchemy)
│   ├── schemas/        # Pydantic schemas
│   ├── routers/        # Auth, Dashboard, Reports
│   ├── services/       # Scanner service (integra motor CLI)
│   ├── deps/           # Auth dependencies
│   └── main.py         # FastAPI app
├── templates/          # HTML (Login, Register, Dashboard, Reports)
├── static/             # CSS/JS/IMG
└── run.py              # Server launcher
```

## Características Implementadas

- ✅ **Autenticación**: Registro/Login con sesiones (cookies + JWT)
- ✅ **Dashboard**: Panel principal con nuevo escaneo
- ✅ **Sistema de créditos**: 3 créditos gratis por usuario
- ✅ **Integración con motor CLI**: Usa `modules/` existentes sin tocar nada
- ✅ **Reportes por usuario**: Cada usuario ve solo sus reportes
- ✅ **Descarga MD/JSON**: Desde dashboard
- ✅ **Procesamiento en background**: Escaneos asíncronos
- ✅ **Base de datos SQLite**: Lista para usar

## Arrancar el servidor web

```bash
cd /home/kali/shadow-it-data-leak-finder
source venv/bin/activate
python web/run.py
```

Abrir: http://127.0.0.1:8000

## Flujo de uso

1. Ir a `/register` - Crear cuenta (recibe 3 créditos)
2. Login en `/login`
3. En Dashboard: poner dominio/organización y click "Iniciar Auditoría"
4. Esperar a que termine (se procesa en background)
5. Ver/Descargar reporte desde dashboard

## Siguiente paso

**PARAR AQUÍ como pediste.** Ahora dime cómo quieres que sea el frontend exactamente:
- Colores, diseño, logo
- ¿Quieres cambiar algo del dashboard?
- ¿Añadir algo más además de login + dashboard?
- etc.

Yo no toco el frontend hasta que me digas las indicaciones exactas.
