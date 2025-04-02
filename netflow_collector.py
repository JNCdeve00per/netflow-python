#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NetFlow Collector para InfluxDB
Este script recibe datos NetFlow y los almacena en una base de datos InfluxDB.
"""

import socket
import struct
import time
import datetime
import sys
import signal
import logging
import argparse
import json
import ipaddress
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

# Configuración del logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('netflow-collector')

# Clase para procesar datos NetFlow v5
class NetflowV5:
    """Clase para procesar paquetes NetFlow versión 5"""
    
    def __init__(self):
        self.header_format = "!HHIIIIBBH"
        self.record_format = "!IIIIHHHBBBBHHBBH"
        self.header_size = struct.calcsize(self.header_format)
        self.record_size = struct.calcsize(self.record_format)
    
    def parse_header(self, data):
        """Parsea la cabecera de NetFlow v5"""
        unpacked = struct.unpack(self.header_format, data[:self.header_size])
        header = {
            'version': unpacked[0],
            'count': unpacked[1],
            'sys_uptime': unpacked[2],
            'unix_secs': unpacked[3],
            'unix_nsecs': unpacked[4],
            'flow_sequence': unpacked[5],
            'engine_type': unpacked[6],
            'engine_id': unpacked[7],
            'sampling_interval': unpacked[8]
        }
        return header
    
    def parse_record(self, data, offset):
        """Parsea un registro de NetFlow v5"""
        record_data = data[offset:offset+self.record_size]
        unpacked = struct.unpack(self.record_format, record_data)
        record = {
            'src_addr': str(ipaddress.IPv4Address(unpacked[0])),
            'dst_addr': str(ipaddress.IPv4Address(unpacked[1])),
            'next_hop': str(ipaddress.IPv4Address(unpacked[2])),
            'input': unpacked[3],
            'output': unpacked[4],
            'dPkts': unpacked[5],
            'dOctets': unpacked[6],
            'first': unpacked[7],
            'last': unpacked[8],
            'src_port': unpacked[9],
            'dst_port': unpacked[10],
            'tcp_flags': unpacked[11],
            'prot': unpacked[12],
            'tos': unpacked[13],
            'src_as': unpacked[14],
            'dst_as': unpacked[15],
            'src_mask': unpacked[16],
            'dst_mask': unpacked[17]
        }
        return record

    def parse_packet(self, data, source_ip):
        """Parsea un paquete completo de NetFlow v5"""
        header = self.parse_header(data)
        records = []
        
        if header['version'] != 5:
            logger.warning(f"Se recibió un paquete de versión {header['version']}, no v5")
            return None
        
        offset = self.header_size
        for i in range(header['count']):
            record = self.parse_record(data, offset)
            record['router'] = source_ip
            record['timestamp'] = header['unix_secs']
            records.append(record)
            offset += self.record_size
        
        return {
            'header': header,
            'records': records
        }

# Clase para procesar datos NetFlow v9
class NetflowV9:
    """Clase para procesar paquetes NetFlow versión 9"""
    
    def __init__(self):
        self.header_format = "!HHIIII"
        self.header_size = struct.calcsize(self.header_format)
        self.templates = {}  # Almacena plantillas por (source_ip, source_id, template_id)
    
    def parse_header(self, data):
        """Parsea la cabecera de NetFlow v9"""
        unpacked = struct.unpack(self.header_format, data[:self.header_size])
        header = {
            'version': unpacked[0],
            'count': unpacked[1],
            'sys_uptime': unpacked[2],
            'unix_secs': unpacked[3],
            'sequence': unpacked[4],
            'source_id': unpacked[5]
        }
        return header
    
    def parse_flowset(self, data, offset, flowset_id, length, source_ip, source_id, timestamp):
        """Parsea un flowset de NetFlow v9"""
        if flowset_id == 0:  # Template FlowSet
            return self.parse_template(data, offset, length, source_ip, source_id)
        elif flowset_id == 1:  # Options Template FlowSet
            logger.debug("Plantillas de opciones no implementadas")
            return []
        elif flowset_id >= 256:  # Data FlowSet
            template = self.templates.get((source_ip, source_id, flowset_id))
            if template:
                return self.parse_data(data, offset, length, template, timestamp)
            else:
                logger.warning(f"No se encontró una plantilla para FlowSet ID {flowset_id}")
                return []
        return []
    
    def parse_template(self, data, offset, length, source_ip, source_id):
        """Parsea una plantilla de NetFlow v9"""
        records = []
        end = offset + length
        
        while offset < end:
            template_id = struct.unpack("!H", data[offset:offset+2])[0]
            field_count = struct.unpack("!H", data[offset+2:offset+4])[0]
            offset += 4
            
            fields = []
            for i in range(field_count):
                field_type = struct.unpack("!H", data[offset:offset+2])[0]
                field_length = struct.unpack("!H", data[offset+2:offset+4])[0]
                fields.append((field_type, field_length))
                offset += 4
            
            self.templates[(source_ip, source_id, template_id)] = fields
            logger.info(f"Nueva plantilla recibida: {source_ip}:{source_id}:{template_id} con {field_count} campos")
        
        return records
    
    def parse_data(self, data, offset, length, template, timestamp):
        """Parsea datos de flujo usando una plantilla"""
        records = []
        end = offset + length
        
        while offset + sum(field[1] for field in template) <= end:
            record = {'timestamp': timestamp}
            
            for field_type, field_length in template:
                field_data = data[offset:offset+field_length]
                offset += field_length
                
                if field_type == 8:  # IPv4 SRC_ADDR
                    if field_length == 4:
                        record['src_addr'] = str(ipaddress.IPv4Address(struct.unpack("!I", field_data)[0]))
                elif field_type == 12:  # IPv4 DST_ADDR
                    if field_length == 4:
                        record['dst_addr'] = str(ipaddress.IPv4Address(struct.unpack("!I", field_data)[0]))
                elif field_type == 7:  # L4_SRC_PORT
                    if field_length == 2:
                        record['src_port'] = struct.unpack("!H", field_data)[0]
                elif field_type == 11:  # L4_DST_PORT
                    if field_length == 2:
                        record['dst_port'] = struct.unpack("!H", field_data)[0]
                elif field_type == 4:  # PROTOCOL
                    if field_length == 1:
                        record['prot'] = struct.unpack("!B", field_data)[0]
                elif field_type == 1:  # IN_BYTES
                    if field_length == 4:
                        record['dOctets'] = struct.unpack("!I", field_data)[0]
                elif field_type == 2:  # IN_PKTS
                    if field_length == 4:
                        record['dPkts'] = struct.unpack("!I", field_data)[0]
                elif field_type == 10:  # INPUT_SNMP
                    if field_length == 2:
                        record['input'] = struct.unpack("!H", field_data)[0]
                elif field_type == 14:  # OUTPUT_SNMP
                    if field_length == 2:
                        record['output'] = struct.unpack("!H", field_data)[0]
                elif field_type == 15:  # IPV4_NEXT_HOP
                    if field_length == 4:
                        record['next_hop'] = str(ipaddress.IPv4Address(struct.unpack("!I", field_data)[0]))
                elif field_type == 6:  # TCP_FLAGS
                    if field_length == 1:
                        record['tcp_flags'] = struct.unpack("!B", field_data)[0]
                elif field_type == 5:  # TOS
                    if field_length == 1:
                        record['tos'] = struct.unpack("!B", field_data)[0]
                elif field_type == 16:  # SRC_AS
                    if field_length == 2 or field_length == 4:
                        if field_length == 2:
                            record['src_as'] = struct.unpack("!H", field_data)[0]
                        else:
                            record['src_as'] = struct.unpack("!I", field_data)[0]
                elif field_type == 17:  # DST_AS
                    if field_length == 2 or field_length == 4:
                        if field_length == 2:
                            record['dst_as'] = struct.unpack("!H", field_data)[0]
                        else:
                            record['dst_as'] = struct.unpack("!I", field_data)[0]
                elif field_type == 9:  # SRC_MASK
                    if field_length == 1:
                        record['src_mask'] = struct.unpack("!B", field_data)[0]
                elif field_type == 13:  # DST_MASK
                    if field_length == 1:
                        record['dst_mask'] = struct.unpack("!B", field_data)[0]
            
            records.append(record)
        
        return records
    
    def parse_packet(self, data, source_ip):
        """Parsea un paquete completo de NetFlow v9"""
        if len(data) < self.header_size:
            logger.warning("Paquete demasiado pequeño para ser NetFlow v9")
            return None
        
        header = self.parse_header(data)
        records = []
        
        if header['version'] != 9:
            logger.warning(f"Se recibió un paquete de versión {header['version']}, no v9")
            return None
        
        offset = self.header_size
        
        while offset < len(data):
            if offset + 4 > len(data):
                break
            
            flowset_id = struct.unpack("!H", data[offset:offset+2])[0]
            flowset_length = struct.unpack("!H", data[offset+2:offset+4])[0]
            
            if flowset_length < 4:
                logger.warning(f"Longitud de FlowSet inválida: {flowset_length}")
                break
            
            flowset_records = self.parse_flowset(
                data, 
                offset + 4, 
                flowset_id, 
                flowset_length - 4, 
                source_ip, 
                header['source_id'],
                header['unix_secs']
            )
            
            for record in flowset_records:
                record['router'] = source_ip
            
            records.extend(flowset_records)
            
            # Avanzar al siguiente FlowSet (con alineación de 4 bytes)
            offset += flowset_length
            padding = (4 - (flowset_length % 4)) % 4
            offset += padding
        
        return {
            'header': header,
            'records': records
        }

# Clase para manejar la conexión a InfluxDB
class InfluxDBWriter:
    """Clase para escribir datos en InfluxDB"""
    
    def __init__(self, url, token, org, bucket):
        self.client = InfluxDBClient(url=url, token=token, org=org)
        self.write_api = self.client.write_api(write_options=SYNCHRONOUS)
        self.bucket = bucket
        self.org = org
        self.batch = []
        self.batch_size = 500
        self.last_write_time = time.time()
    
    def add_record(self, record):
        """Añade un registro al lote para escritura"""
        try:
            # Crear un punto de InfluxDB a partir del registro
            point = Point("netflow")
            
            # Añadir etiquetas (índices)
            if 'router' in record:
                point = point.tag("router", record['router'])
            if 'src_addr' in record:
                point = point.tag("src_addr", record['src_addr'])
            if 'dst_addr' in record:
                point = point.tag("dst_addr", record['dst_addr'])
            if 'prot' in record:
                point = point.tag("protocol", str(record['prot']))
            if 'src_port' in record and 'dst_port' in record:
                point = point.tag("src_port", str(record['src_port']))
                point = point.tag("dst_port", str(record['dst_port']))
            
            # Añadir campos (valores)
            if 'dPkts' in record:
                point = point.field("packets", record['dPkts'])
            if 'dOctets' in record:
                point = point.field("bytes", record['dOctets'])
            if 'next_hop' in record:
                point = point.field("next_hop", record['next_hop'])
            if 'input' in record:
                point = point.field("input_int", record['input'])
            if 'output' in record:
                point = point.field("output_int", record['output'])
            if 'tcp_flags' in record:
                point = point.field("tcp_flags", record['tcp_flags'])
            if 'tos' in record:
                point = point.field("tos", record['tos'])
            if 'src_as' in record:
                point = point.field("src_as", record['src_as'])
            if 'dst_as' in record:
                point = point.field("dst_as", record['dst_as'])
            if 'src_mask' in record:
                point = point.field("src_mask", record['src_mask'])
            if 'dst_mask' in record:
                point = point.field("dst_mask", record['dst_mask'])
            
            # Establecer timestamp si está disponible
            if 'timestamp' in record:
                point = point.time(datetime.datetime.fromtimestamp(record['timestamp']), write_precision='s')
            
            self.batch.append(point)
            
            # Escribir lote si alcanza el tamaño o el tiempo límite
            current_time = time.time()
            if len(self.batch) >= self.batch_size or (current_time - self.last_write_time) > 10:
                self.write_batch()
                
        except Exception as e:
            logger.error(f"Error al crear punto para InfluxDB: {e}")
    
    def write_batch(self):
        """Escribe el lote actual en InfluxDB"""
        if not self.batch:
            return
            
        try:
            self.write_api.write(bucket=self.bucket, org=self.org, record=self.batch)
            logger.info(f"Escritos {len(self.batch)} registros en InfluxDB")
            self.batch = []
            self.last_write_time = time.time()
        except Exception as e:
            logger.error(f"Error al escribir en InfluxDB: {e}")
    
    def close(self):
        """Cierra la conexión a InfluxDB después de escribir cualquier registro pendiente"""
        self.write_batch()
        self.write_api.close()
        self.client.close()

# Clase principal para recolectar NetFlow
class NetflowCollector:
    """Clase principal para recolectar datos NetFlow"""
    
    def __init__(self, config):
        self.config = config
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((config['listen_ip'], config['listen_port']))
        self.running = True
        
        # Inicializar procesadores de NetFlow
        self.netflow_v5 = NetflowV5()
        self.netflow_v9 = NetflowV9()
        
        # Inicializar escritor de InfluxDB
        self.influx_writer = InfluxDBWriter(
            config['influx_url'],
            config['influx_token'],
            config['influx_org'],
            config['influx_bucket']
        )
        
        # Configurar manejo de señales
        signal.signal(signal.SIGINT, self.handle_signal)
        signal.signal(signal.SIGTERM, self.handle_signal)
    
    def handle_signal(self, sig, frame):
        """Maneja señales para una terminación limpia"""
        logger.info("Señal recibida, deteniendo el colector...")
        self.running = False
    
    def process_packet(self, data, addr):
        """Procesa un paquete NetFlow"""
        source_ip = addr[0]
        
        if len(data) < 2:
            logger.warning(f"Paquete demasiado pequeño de {source_ip}")
            return
        
        version = struct.unpack("!H", data[0:2])[0]
        
        if version == 5:
            parsed = self.netflow_v5.parse_packet(data, source_ip)
        elif version == 9:
            parsed = self.netflow_v9.parse_packet(data, source_ip)
        else:
            logger.warning(f"Versión de NetFlow no soportada: {version} desde {source_ip}")
            return
        
        if parsed and 'records' in parsed:
            record_count = len(parsed['records'])
            if record_count > 0:
                logger.info(f"Recibidos {record_count} registros NetFlow v{version} desde {source_ip}")
                for record in parsed['records']:
                    self.influx_writer.add_record(record)
    
    def run(self):
        """Ejecuta el bucle principal del colector"""
        logger.info(f"Iniciando colector NetFlow en {self.config['listen_ip']}:{self.config['listen_port']}")
        
        self.sock.settimeout(1.0)  # Timeout para verificar periódicamente si debemos detenernos
        
        while self.running:
            try:
                data, addr = self.sock.recvfrom(8192)
                self.process_packet(data, addr)
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Error al procesar datos: {e}")
        
        # Limpieza
        logger.info("Cerrando colector NetFlow")
        self.influx_writer.close()
        self.sock.close()

# Función principal
def main():
    parser = argparse.ArgumentParser(description='NetFlow Collector para InfluxDB')
    parser.add_argument('-c', '--config', type=str, default='config.json', help='Ruta al archivo de configuración JSON')
    args = parser.parse_args()
    
    try:
        with open(args.config, 'r') as f:
            config = json.load(f)
    except Exception as e:
        logger.error(f"Error al cargar configuración: {e}")
        config = {
            'listen_ip': '0.0.0.0',
            'listen_port': 9995,
            'influx_url': 'http://localhost:8086',
            'influx_token': 'your-token-here',
            'influx_org': 'your-org',
            'influx_bucket': 'netflow'
        }
        
        # Guardar configuración predeterminada si no existe
        try:
            with open(args.config, 'w') as f:
                json.dump(config, f, indent=2)
            logger.info(f"Configuración predeterminada guardada en {args.config}")
        except Exception as e:
            logger.error(f"No se pudo guardar la configuración predeterminada: {e}")
    
    collector = NetflowCollector(config)
    collector.run()

if __name__ == "__main__":
    main()
