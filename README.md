# NetFlow Collector para InfluxDB

Esta aplicación Python recolecta datos NetFlow y los almacena en una base de datos InfluxDB. Es similar al proyecto [nfCollector](https://github.com/javadmohebbi/nfCollector.git) pero con un enfoque en Python.

## Características

- Soporte para NetFlow versión 5 y 9
- Procesamiento eficiente de flujos de red
- Almacenamiento en InfluxDB para análisis posterior
- Configuración sencilla mediante archivo JSON
- Manejo de lotes para optimizar la escritura en la base de datos

## Requisitos

- Python 3.6+
- InfluxDB 2.0+
- Biblioteca `influxdb-client`

## Instalación

1. Clona este repositorio:
   ```
   git clone https://github.com/tuusuario/netflow-to-influxdb.git
   cd netflow-to-influxdb
   ```

2. Instala las dependencias:
   ```
   pip install influxdb-client
   ```

3. Crea y configura el archivo `config.json` (se generará automáticamente con valores predeterminados si no existe):

## Configuración

Edita el archivo `config.json` con tus parámetros:

```json
{
  "listen_ip": "0.0.0.0",
  "listen_port": 9995,
  "influx_url": "http://localhost:8086",
  "influx_token": "tu-token-de-influxdb-aqui",
  "influx_org": "tu-organizacion",
  "influx_bucket": "netflow"
}
```

- `listen_ip`: Dirección IP donde escuchar (0.0.0.0 para todas las interfaces)
- `listen_port`: Puerto UDP para recibir datos NetFlow
- `influx_url`: URL de tu servidor InfluxDB
- `influx_token`: Token de API de InfluxDB
- `influx_org`: Nombre de tu organización en InfluxDB
- `influx_bucket`: Nombre del bucket donde se almacenarán los datos

## Uso

Ejecuta la aplicación:

```
python netflow_collector.py
```

O con una ruta personalizada al archivo de configuración:

```
python netflow_collector.py -c /ruta/a/tu/config.json
```

## Configuración de dispositivos de red

Configura tus routers, switches o firewalls para enviar datos NetFlow al host donde ejecutas esta aplicación, usando el puerto especificado en la configuración.

### Ejemplo para Cisco IOS

```
ip flow-export version 9
ip flow-export destination 192.168.1.100 9995
ip flow-export source GigabitEthernet0/1
ip flow-cache timeout active 1
ip flow-cache timeout inactive 15
ip flow-export template refresh-rate 15
```

### Ejemplo para MikroTik RouterOS

```
/ip traffic-flow
set enabled=yes
set active-flow-timeout=1m
set inactive-flow-timeout=15s
/ip traffic-flow target
add address=192.168.1.100 port=9995 version=9
```

## Datos capturados

La aplicación almacena los siguientes datos en InfluxDB:

- Direcciones IP de origen y destino
- Puertos de origen y destino
- Protocolo
- Bytes y paquetes transferidos
- Interfaces de entrada y salida
- Flags TCP
- TOS (Type of Service)
- ASN de origen y destino
- Máscaras de red

## Visualización

Para visualizar los datos recolectados, puedes usar Grafana conectado a tu InfluxDB. Crea dashboards que consulten la medición "netflow" en tu bucket.

