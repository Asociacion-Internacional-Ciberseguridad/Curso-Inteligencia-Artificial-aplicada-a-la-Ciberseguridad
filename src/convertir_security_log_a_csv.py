#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
convertir_security_log_a_csv.py

OBJETIVO
--------
Convertir un archivo de log de seguridad de Windows en formato texto
a un archivo CSV, sin simular datos, sin enriquecer datos y sin inventar
columnas.

Este programa está diseñado para el archivo security.log que tiene líneas
con esta estructura:

    2026-04-25 00:01:03|Host=WIN-SRV-FILE01|Provider=Microsoft-Windows-Security-Auditing|Channel=Security|EventID=4624|...

Es decir:

1. La primera parte antes del primer carácter "|" es la fecha y hora.
2. Luego vienen varios campos separados por "|".
3. Cada campo posterior usa el formato Clave=Valor.
4. El campo Message puede contener espacios, barras invertidas, IPs, etc.
5. El programa NO interpreta si el evento es ataque o no.
6. El programa NO agrega geolocalización.
7. El programa NO agrega columnas artificiales.
8. El programa solo convierte el log plano a una tabla CSV.

USO BÁSICO
----------
    python convertir_security_log_a_csv.py --input security.log --output security_convertido.csv

USO CON RUTAS
-------------
    python convertir_security_log_a_csv.py --input logs/security.log --output datasets/security.csv

SALIDA
------
El CSV tendrá estas columnas:

    timestamp
    host
    provider
    channel
    event_id
    event_name
    domain
    user
    workstation
    source_ip
    source_port
    logon_type
    process
    status
    sub_status
    message

Estas columnas salen directamente del log.
La única transformación aplicada es cambiar el nombre de las claves
del log a nombres de columna más cómodos para pandas:

    Host       -> host
    EventID    -> event_id
    SourceIP   -> source_ip
    SourcePort -> source_port
    LogonType  -> logon_type
    SubStatus  -> sub_status

Por ejemplo, esta parte del log:

    EventID=4624

se convierte en el CSV como:

    event_id,4624
"""

# ============================================================================
# IMPORTACIÓN DE LIBRERÍAS
# ============================================================================

# argparse permite recibir parámetros desde la línea de comandos.
# En este programa se usa para indicar:
#   --input  archivo de entrada, por ejemplo security.log
#   --output archivo de salida, por ejemplo security.csv
import argparse

# csv es una librería estándar de Python para escribir archivos CSV correctamente.
# Es mejor usar csv.DictWriter que armar líneas manualmente con comas, porque:
#   - protege textos que contienen comas,
#   - maneja comillas correctamente,
#   - mantiene el orden de las columnas.
import csv

# Path permite trabajar con rutas de archivos de forma clara y portable.
# Funciona bien en Windows, Linux y macOS.
from pathlib import Path


# ============================================================================
# DEFINICIÓN DE COLUMNAS DEL CSV
# ============================================================================

# Lista de columnas finales que tendrá el archivo CSV.
# IMPORTANTE:
# Estas columnas corresponden a los campos reales del log.
# No se agregan columnas de geolocalización, clasificación, ataque,
# latitud, longitud, país, ciudad, ni ningún otro dato simulado.
COLUMNAS_CSV = [
    "timestamp",
    "host",
    "provider",
    "channel",
    "event_id",
    "event_name",
    "domain",
    "user",
    "workstation",
    "source_ip",
    "source_port",
    "logon_type",
    "process",
    "status",
    "sub_status",
    "message",
]


# ============================================================================
# MAPEO ENTRE CLAVES DEL LOG Y NOMBRES DE COLUMNAS DEL CSV
# ============================================================================

# En el log las claves vienen con nombres como:
#   Host
#   Provider
#   EventID
#   SourceIP
#
# Para trabajar mejor en pandas, normalmente conviene usar nombres en minúscula
# y con guion bajo cuando hay palabras compuestas:
#   EventID    -> event_id
#   SourceIP   -> source_ip
#   SourcePort -> source_port
#
# Este diccionario indica cómo transformar cada clave del log al nombre
# de columna final del CSV.
MAPEO_CLAVES = {
    "Host": "host",
    "Provider": "provider",
    "Channel": "channel",
    "EventID": "event_id",
    "EventName": "event_name",
    "Domain": "domain",
    "User": "user",
    "Workstation": "workstation",
    "SourceIP": "source_ip",
    "SourcePort": "source_port",
    "LogonType": "logon_type",
    "Process": "process",
    "Status": "status",
    "SubStatus": "sub_status",
    "Message": "message",
}


# ============================================================================
# FUNCIÓN: crear_fila_vacia
# ============================================================================

def crear_fila_vacia():
    """
    Crea un diccionario vacío con todas las columnas esperadas.

    ¿Por qué se hace esto?
    ----------------------
    Porque puede ocurrir que alguna línea del log no tenga algún campo.
    Por ejemplo, una línea podría no traer SourcePort o LogonType.

    Si creamos la fila desde el inicio con todas las columnas,
    garantizamos que el CSV siempre tenga una estructura uniforme.

    Retorna
    -------
    dict
        Diccionario con todas las columnas inicializadas como cadena vacía.
    """

    # Se usa comprensión de diccionario.
    # Para cada columna en COLUMNAS_CSV, se crea una clave con valor "".
    return {columna: "" for columna in COLUMNAS_CSV}


# ============================================================================
# FUNCIÓN: convertir_valor
# ============================================================================

def convertir_valor(nombre_columna, valor):
    """
    Convierte algunos valores numéricos para que pandas los lea mejor.

    Parámetros
    ----------
    nombre_columna : str
        Nombre de la columna final del CSV.
        Ejemplo: event_id, source_port, logon_type.

    valor : str
        Valor original leído desde el log.

    Retorna
    -------
    int o str
        - int cuando el campo debería ser numérico y el valor es válido.
        - str cuando el campo debe mantenerse como texto.

    Nota importante
    ---------------
    Esta función NO inventa información.
    Solo convierte textos numéricos a enteros.

    Ejemplo:
        "4624" -> 4624
        "65486" -> 65486

    Los campos como status y sub_status se dejan como texto porque tienen
    formato hexadecimal, por ejemplo:
        0x0
        0xC000006D
    """

    # Estas columnas son numéricas en el log y conviene que en el CSV
    # queden como números para análisis posterior con pandas.
    columnas_enteras = {"event_id", "source_port", "logon_type"}

    # Si la columna es numérica, se intenta convertir a entero.
    if nombre_columna in columnas_enteras:
        try:
            return int(valor)
        except ValueError:
            # Si por alguna razón el valor no puede convertirse,
            # se devuelve el valor original para no perder información.
            return valor

    # Para el resto de columnas se conserva el valor como texto.
    return valor


# ============================================================================
# FUNCIÓN: parsear_linea
# ============================================================================

def parsear_linea(linea):
    """
    Convierte una línea del archivo security.log en un diccionario.

    Parámetros
    ----------
    linea : str
        Línea completa del archivo log.

    Retorna
    -------
    dict o None
        - dict con los campos parseados si la línea es válida.
        - None si la línea está vacía o no tiene una estructura mínima válida.

    Ejemplo de entrada
    ------------------
    2026-04-25 00:01:03|Host=WIN-SRV-FILE01|Provider=Microsoft-Windows-Security-Auditing|...

    Resultado esperado
    ------------------
    {
        "timestamp": "2026-04-25 00:01:03",
        "host": "WIN-SRV-FILE01",
        "provider": "Microsoft-Windows-Security-Auditing",
        ...
    }
    """

    # strip() elimina saltos de línea y espacios sobrantes al inicio/final.
    linea = linea.strip()

    # Si la línea está vacía, no hay nada que convertir.
    if not linea:
        return None

    # El log usa el carácter "|" como separador principal.
    # split("|") divide la línea en partes.
    #
    # Ejemplo:
    #   "fecha|Host=PC01|EventID=4624"
    #
    # se convierte en:
    #   ["fecha", "Host=PC01", "EventID=4624"]
    partes = linea.split("|")

    # Para que una línea sea útil, al menos debe tener:
    #   partes[0] = timestamp
    #   partes[1] = algún campo tipo Clave=Valor
    if len(partes) < 2:
        return None

    # Creamos una fila con todas las columnas vacías.
    fila = crear_fila_vacia()

    # La primera parte de la línea es la fecha y hora.
    # No viene como "Timestamp=...", sino directamente como texto.
    fila["timestamp"] = partes[0].strip()

    # Recorremos todas las partes después del timestamp.
    # Cada una debería tener formato Clave=Valor.
    for parte in partes[1:]:

        # Si por error existe un campo vacío, lo ignoramos.
        if not parte:
            continue

        # Separamos solamente en el primer "=".
        #
        # IMPORTANTE:
        # Usamos split("=", 1) y no split("=") porque el valor podría
        # contener otro signo "=" en algunos logs reales.
        #
        # Ejemplo:
        #   Message=Texto con a=b
        #
        # Con split("=", 1) se mantiene todo lo que está después
        # del primer "=" como valor completo.
        if "=" not in parte:
            # Si una parte no tiene "=", no cumple Clave=Valor.
            # La ignoramos para evitar romper el programa.
            continue

        clave, valor = parte.split("=", 1)

        # Limpiamos espacios sobrantes.
        clave = clave.strip()
        valor = valor.strip()

        # Buscamos si la clave del log está en nuestro mapeo.
        # Si no está, significa que es un campo no contemplado
        # y lo ignoramos para mantener el CSV con las columnas esperadas.
        if clave not in MAPEO_CLAVES:
            continue

        # Convertimos la clave original del log al nombre de columna final.
        nombre_columna = MAPEO_CLAVES[clave]

        # Convertimos algunos campos numéricos a enteros.
        valor_convertido = convertir_valor(nombre_columna, valor)

        # Guardamos el valor en la fila.
        fila[nombre_columna] = valor_convertido

    return fila


# ============================================================================
# FUNCIÓN: convertir_log_a_csv
# ============================================================================

def convertir_log_a_csv(ruta_log, ruta_csv):
    """
    Lee el archivo security.log y genera el archivo security.csv.

    Parámetros
    ----------
    ruta_log : str o Path
        Ruta del archivo de entrada.

    ruta_csv : str o Path
        Ruta del archivo CSV de salida.

    Retorna
    -------
    tuple
        Una tupla con:
        - total_lineas: cantidad de líneas leídas del log.
        - total_convertidas: cantidad de filas escritas en el CSV.
        - total_ignoradas: cantidad de líneas vacías o inválidas.

    Flujo de trabajo
    ----------------
    1. Abrir el archivo security.log en modo lectura.
    2. Abrir el archivo security.csv en modo escritura.
    3. Escribir la cabecera del CSV.
    4. Leer cada línea del log.
    5. Parsear cada línea.
    6. Escribir cada fila válida en el CSV.
    """

    # Convertimos las rutas a objetos Path.
    ruta_log = Path(ruta_log)
    ruta_csv = Path(ruta_csv)

    # Verificamos que el archivo de entrada exista.
    # Si no existe, se lanza un error claro.
    if not ruta_log.exists():
        raise FileNotFoundError(f"No existe el archivo de entrada: {ruta_log}")

    # Si la carpeta donde se grabará el CSV no existe, la creamos.
    # parents=True permite crear carpetas intermedias.
    # exist_ok=True evita error si la carpeta ya existe.
    if ruta_csv.parent and str(ruta_csv.parent) != ".":
        ruta_csv.parent.mkdir(parents=True, exist_ok=True)

    # Contadores para mostrar un resumen al final.
    total_lineas = 0
    total_convertidas = 0
    total_ignoradas = 0

    # Abrimos el archivo log con encoding utf-8.
    # errors="replace" evita que el programa se caiga si aparece algún
    # carácter extraño; en ese caso lo reemplaza por un carácter válido.
    with ruta_log.open("r", encoding="utf-8", errors="replace") as archivo_log:

        # Abrimos el CSV en modo escritura.
        #
        # newline="" es recomendado por la documentación de Python cuando
        # se usa la librería csv. Evita líneas en blanco extra en Windows.
        with ruta_csv.open("w", encoding="utf-8", newline="") as archivo_csv:

            # DictWriter permite escribir diccionarios como filas CSV.
            # fieldnames define el orden exacto de las columnas.
            escritor = csv.DictWriter(
                archivo_csv,
                fieldnames=COLUMNAS_CSV,
                delimiter=",",
                quoting=csv.QUOTE_MINIMAL
            )

            # Escribimos la primera fila del CSV: la cabecera.
            escritor.writeheader()

            # Leemos el log línea por línea.
            # Esto es mejor que cargar todo el archivo en memoria,
            # especialmente si el log es grande.
            for linea in archivo_log:

                # Aumentamos el contador total de líneas leídas.
                total_lineas += 1

                # Convertimos la línea a un diccionario.
                fila = parsear_linea(linea)

                # Si la fila es None, la línea estaba vacía o inválida.
                if fila is None:
                    total_ignoradas += 1
                    continue

                # Escribimos la fila válida en el CSV.
                escritor.writerow(fila)

                # Aumentamos el contador de filas convertidas.
                total_convertidas += 1

    return total_lineas, total_convertidas, total_ignoradas


# ============================================================================
# FUNCIÓN: construir_parser_argumentos
# ============================================================================

def construir_parser_argumentos():
    """
    Construye el parser de argumentos de línea de comandos.

    Esto permite ejecutar el programa así:

        python convertir_security_log_a_csv.py --input security.log --output security.csv

    Retorna
    -------
    argparse.ArgumentParser
        Parser configurado para recibir rutas de entrada y salida.
    """

    parser = argparse.ArgumentParser(
        description="Convierte un archivo security.log de Windows a security.csv sin enriquecer datos."
    )

    # Argumento obligatorio: archivo de entrada.
    parser.add_argument(
        "--input",
        required=True,
        help="Ruta del archivo security.log de entrada."
    )

    # Argumento obligatorio: archivo de salida.
    parser.add_argument(
        "--output",
        required=True,
        help="Ruta del archivo security.csv de salida."
    )

    return parser


# ============================================================================
# FUNCIÓN PRINCIPAL
# ============================================================================

def main():
    """
    Función principal del programa.

    Se encarga de:
    1. Leer los argumentos de entrada.
    2. Ejecutar la conversión.
    3. Mostrar un resumen final.
    """

    # Creamos el parser de argumentos.
    parser = construir_parser_argumentos()

    # Leemos los argumentos escritos por el usuario en consola.
    args = parser.parse_args()

    # Ejecutamos la conversión.
    total_lineas, total_convertidas, total_ignoradas = convertir_log_a_csv(
        ruta_log=args.input,
        ruta_csv=args.output
    )

    # Mostramos un resumen final para validar rápidamente el resultado.
    print("Conversión finalizada correctamente.")
    print(f"Archivo de entrada : {args.input}")
    print(f"Archivo de salida  : {args.output}")
    print(f"Líneas leídas      : {total_lineas}")
    print(f"Filas convertidas  : {total_convertidas}")
    print(f"Líneas ignoradas   : {total_ignoradas}")


# ============================================================================
# PUNTO DE ENTRADA DEL SCRIPT
# ============================================================================

# Esta condición indica que main() solo se ejecutará cuando el archivo
# se corra directamente desde consola.
#
# Si en el futuro importas este archivo desde otro programa Python,
# main() no se ejecutará automáticamente.
if __name__ == "__main__":
    main()
