# Shadow IT & Data Leak Finder

**Herramienta SaaS de auditoría defensiva automatizada para detección de Shadow IT y filtraciones de datos.**

## Descripción

Shadow IT & Data Leak Finder es una solución automatizada de seguridad defensiva que:

1. **Recolecta** datos de inteligencia OSINT simulados (subdominios, buckets expuestos, logs, configuraciones)
2. **Analiza** con IA (Big Pickle en OpenCode) actuando como analista SOC defensivo
3. **Identifica** vulnerabilidades de exposición: credenciales en texto plano, buckets abiertos, servidores de desarrollo indexados
4. **Clasifica** riesgos por severidad (Crítico/Alto/Medio/Bajo/Informativo)
5. **Genera** reportes corporativos limpios en formato Markdown

## Arquitectura Modular

```
shadow-it-data-leak-finder/
├── main.py                      # Orquestador principal
├── config/                      # Configuración y logging
├── modules/
│   ├── recon/                   # Módulo OSINT/Reconocimiento
│   ├── api/                     # Conector API OpenCode/Big Pickle
│   ├── ai/                      # Motor de prompts SOC
│   └── reports/                 # Generador de reportes
├── utils/                       # Utilidades, excepciones, reintentos
└── outputs/                     # Reportes generados
```

## Instalación

### Local

```bash
# Clonar o copiar el proyecto
cd shadow-it-data-leak-finder

# Crear entorno virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Instalar dependencias
pip install -r requirements.txt

# Configurar variables de entorno
cp .env.example .env
# Editar .env con tus credenciales
```

### Despliegue en la Nube (24/7)

#### Render (Background Worker)

1. Crear nuevo **Background Worker** en [render.com](https://render.com)
2. Conectar repositorio Git
3. Configuración:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `python main.py`
   - **Environment:** Agregar variables desde `.env.example`
4. Deploy automático

#### Railway (Worker Service)

1. Crear nuevo proyecto en [railway.app](https://railway.app)
2. Deploy from GitHub repo
3. Agregar variables de entorno
4. Railway detectará automáticamente Python
5. Start command: `python main.py`

## Uso

```bash
# Ejecutar una vez
python main.py

# Ejecutar en modo continuo (24/7) - ya implementado en main.py
python main.py
```

## Configuración

Editar `.env` con tus valores:

```env
OPENCODE_API_ENDPOINT=https://api.opencode.ai/v1/chat/completions
OPENCODE_API_KEY=tu_clave_aqui
BIG_PICKLE_MODEL=big-pickle
SCAN_INTERVAL_MINUTES=60
```

## Características

- ✅ **Asíncrono**: Usa `asyncio` y `aiohttp` para máxima eficiencia
- ✅ **Resiliente**: Manejo de rate-limits (429), reintentos con backoff exponencial
- ✅ **Sin caídas**: Continúa funcionando ante errores de red/conexión
- ✅ **Modular**: Fácil de extender con fuentes OSINT reales
- ✅ **Automatizado**: Puede correr 24/7 como worker en la nube
- ✅ **Reportes corporativos**: Formato Markdown listo para clientes
- ✅ **Análisis defensivo**: IA con rol SOC especializado

## Interconexión de Componentes

1. **main.py** → Orquesta todo el flujo
2. **modules/recon/osint_mock.py** → Genera datos crudos de infraestructura
3. **modules/ai/prompt_engine.py** → Construye prompt SOC defensivo
4. **modules/api/opencode_client.py** → Envía datos a Big Pickle vía API
5. **modules/reports/report_generator.py** → Genera reporte Markdown/JSON
6. **config/** → Configuración centralizada
7. **utils/** → Manejo de errores y reintentos

## Seguridad

- Nunca commitear `.env` con credenciales reales
- Las API keys se cargan desde variables de entorno
- Datos sensibles no se logean
- Prompts diseñados con enfoque defensivo únicamente

## Disclaimer

Esta herramienta es **únicamente para fines defensivos y educativos**. Debe usarse solo en entornos propios o con autorización explícita.
