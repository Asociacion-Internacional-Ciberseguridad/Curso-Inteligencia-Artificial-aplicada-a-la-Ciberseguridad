"""
generar_dataset_sintetico_iris.py

Programa básico para generar un dataset sintético tipo Iris.

El dataset generado sirve para probar un modelo de Machine Learning entrenado
con las variables clásicas del dataset Iris:

- sepal_length
- sepal_width
- petal_length
- petal_width
- species

El archivo resultante se guarda como:
iris_sintetico.csv
"""

import numpy as np
import pandas as pd


# ============================================================
# 1. CONFIGURACIÓN GENERAL
# ============================================================

# Cantidad total de registros sintéticos a generar
N_REGISTROS = 300

# Semilla para que los resultados sean reproducibles.
# Si cambias este número, se generarán datos diferentes.
SEMILLA = 42

# Nombre del archivo CSV de salida
ARCHIVO_SALIDA = "iris_sintetico.csv"


# ============================================================
# 2. DEFINICIÓN DE PARÁMETROS POR TIPO DE FLOR
# ============================================================
# Usamos valores aproximados del dataset Iris original.
# Cada especie tendrá una media y una desviación estándar
# para cada característica.

parametros_iris = {
    "setosa": {
        "sepal_length": (5.0, 0.35),
        "sepal_width":  (3.4, 0.30),
        "petal_length": (1.5, 0.20),
        "petal_width":  (0.2, 0.10),
    },
    "versicolor": {
        "sepal_length": (5.9, 0.50),
        "sepal_width":  (2.8, 0.30),
        "petal_length": (4.3, 0.45),
        "petal_width":  (1.3, 0.20),
    },
    "virginica": {
        "sepal_length": (6.6, 0.60),
        "sepal_width":  (3.0, 0.35),
        "petal_length": (5.6, 0.55),
        "petal_width":  (2.0, 0.25),
    },
}


# ============================================================
# 3. FUNCIÓN PARA GENERAR DATOS DE UNA ESPECIE
# ============================================================

def generar_datos_especie(nombre_especie, cantidad, parametros):
    """
    Genera datos sintéticos para una especie de flor.

    Parámetros:
        nombre_especie: nombre de la especie, por ejemplo 'setosa'
        cantidad: número de registros a generar
        parametros: diccionario con medias y desviaciones estándar

    Retorna:
        DataFrame con los datos generados
    """

    datos = {}

    for columna, valores_parametro in parametros.items():
        media, desviacion = valores_parametro

        # Generamos valores aleatorios siguiendo una distribución normal.
        valores = np.random.normal(
            loc=media,
            scale=desviacion,
            size=cantidad
        )

        # Evitamos valores negativos o cero, porque las medidas físicas
        # de pétalos y sépalos no pueden ser negativas.
        valores = np.clip(valores, a_min=0.1, a_max=None)

        # Redondeamos a 2 decimales para que el dataset sea más legible.
        datos[columna] = np.round(valores, 2)

    # Agregamos la columna con la especie real.
    datos["species"] = nombre_especie

    return pd.DataFrame(datos)


# ============================================================
# 4. GENERACIÓN DEL DATASET COMPLETO
# ============================================================

def main():
    """
    Función principal del programa.
    """

    np.random.seed(SEMILLA)

    especies = list(parametros_iris.keys())

    # Distribuimos la cantidad de registros entre las tres especies.
    cantidad_por_especie = N_REGISTROS // len(especies)

    dataframes = []

    for especie in especies:
        df_especie = generar_datos_especie(
            nombre_especie=especie,
            cantidad=cantidad_por_especie,
            parametros=parametros_iris[especie]
        )

        dataframes.append(df_especie)

    # Unimos los registros de todas las especies.
    df_final = pd.concat(dataframes, ignore_index=True)

    # Mezclamos las filas para que no queden ordenadas por especie.
    df_final = df_final.sample(frac=1, random_state=SEMILLA).reset_index(drop=True)

    # Guardamos el dataset en CSV.
    df_final.to_csv(ARCHIVO_SALIDA, index=False, encoding="utf-8")

    print("Dataset sintético generado correctamente.")
    print(f"Archivo creado: {ARCHIVO_SALIDA}")
    print(f"Cantidad de registros: {len(df_final)}")
    print()
    print("Primeras filas del dataset:")
    print(df_final.head())


# ============================================================
# 5. EJECUCIÓN DEL PROGRAMA
# ============================================================

if __name__ == "__main__":
    main()
