# IoC Knowledge Engine

Este proyecto implementa una prueba de concepto (PoC) sobre el **Diseño de un algoritmo de generación de conocimiento** a partir de Indicadores de Compromiso (IoC) y demás datos de diferentes verticales.

**Estos resultados han sido (parcialmente) financiados por la Cátedra Internacional UMA 2023, la cual forma parte del Programa Global de Innovación en Seguridad para la promoción de Cátedras de Ciberseguridad en España financiado por la Unión Europea Fondos NextGeneration-EU, a través del Instituto Nacional de Ciberseguridad (INCIBE).**

### ¿En qué consiste?

Se ha diseñado el algoritmo para que actúe como un motor analítico central. La idea es que se alimente continuamente de flujos de datos y telemetría (trazas de red, clasificaciones de malware impulsadas por diferentes módulos, y logs de honeypots como GenPot). A partir de ahí, cruza estos datos y, utilizando un enfoque **RAG (Retrieval-Augmented Generation)** con un LLM, genera conocimientos avanzados sobre los ataques.

En esta PoC se ha utilizado:

- Base de conocimiento estructurada de **MITRE ATT&CK**.
- Búsqueda semántica usando `FAISS` y `sentence-transformers` (`all-MiniLM-L6-v2`) para extraer las técnicas que mejor encajan con el ataque.
- Un LLM en local (`google/flan-t5-base` para probar en CPU sin agotar la memoria) que recibe el contexto de MITRE y la telemetría resumida, y nos devuelve un análisis estructurado de TTPs, riesgos y recomendaciones.

## Funcionamiento

Para lanzar y probar el algoritmo en local, solo es necesario clonar el repositorio y descargar las dependencias:

```bash
git clone https://github.com/antoniol00/IoC-Knowledge-Engine.git
cd IoC-Knowledge-Engine

pip install -r requirements.txt
```

## Ejecución

Existen varios cenarios simulados para probar la solución. Trazas de red, archivos, IoCs y todo está ya modelado en el directorio `data/`.

Para ver la lista de escenarios disponibles:

```bash
python main.py --list
```

Para procesar un escenario concreto:

```bash
python main.py --scenario 1
```

## Estructura de ficheros

- `main.py` -> Interfaz de línea de comandos para probar el motor.
- `data/` -> JSON con la telemetría curada y la base de conocimiento de MITRE ATT&CK en español/inglés.
- `src/knowledge_base.py` -> Módulo que encapsula a FAISS y los embeddings.
- `src/knowledge_engine.py` -> Conecta los resultados de la base de conocimiento con las llamadas al LLM de HuggingFace.
- `src/telemetry_processor.py` -> Transforma información a resúmenes naturales para facilitárselo a la IA.
- `src/demo_scenarios.py` -> Constantes y metadatos de los escenarios de prueba.
