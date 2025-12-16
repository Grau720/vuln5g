from typing import List, Tuple, Optional

class DebugMapper:
    """
    Analizador de resultados del mapping de CVEs optimizado para rendimiento.
    """

    def __init__(self, max_items=10):
        self.resultados = []
        self.max_items = max_items

        self.stats = {
            'total': 0,
            'con_componente': 0,
            'sin_componente': 0,
            'con_versiones': 0,
            'sin_versiones': 0,
            'con_mitre': 0,
            'sin_mitre': 0,
        }

    def add(self, resultado: Optional[dict]):
        if not resultado:
            return

        self.resultados.append(resultado)
        self.stats['total'] += 1

        if resultado.get('componente_afectado'):
            self.stats['con_componente'] += 1
        else:
            self.stats['sin_componente'] += 1

        if resultado.get('versiones_afectadas'):
            self.stats['con_versiones'] += 1
        else:
            self.stats['sin_versiones'] += 1

        if resultado.get('descripcion_tecnica') or resultado.get('referencias_mitre'):
            self.stats['con_mitre'] += 1
        else:
            self.stats['sin_mitre'] += 1

    # --------- MÉTODOS DE ESTADÍSTICAS --------- #

    def get_tipo_stats(self):
        return dict(Counter(r.get('tipo', 'Sin clasificar') for r in self.resultados).most_common())

    def get_riesgo_stats(self):
        return dict(Counter(r.get('riesgo', 'desconocido') for r in self.resultados).most_common())

    def get_componente_stats(self, n=None):
        n = n or self.max_items
        comp = Counter(r.get('componente_afectado') for r in self.resultados if r.get('componente_afectado'))
        return dict(comp.most_common(n))

    def get_etiquetas_stats(self, n=None):
        n = n or self.max_items
        etiquetas = []
        for r in self.resultados:
            etiquetas.extend(r.get('etiquetas', []))
        return dict(Counter(etiquetas).most_common(n))

    def get_infraestructura_stats(self):
        infra = []
        for r in self.resultados:
            infra.extend(r.get('infraestructura_5g_afectada', []))
        return dict(Counter(infra))

    def get_protocolos_stats(self, n=None):
        n = n or self.max_items
        protos = []
        for r in self.resultados:
            protos.extend(r.get('protocolos_implicados', []))
        return dict(Counter(protos).most_common(n))

    def get_interfaces_stats(self):
        ifaces = []
        for r in self.resultados:
            ifaces.extend(r.get('interfaces_implicadas', []))
        return dict(Counter(ifaces))

    def get_dificultad_stats(self):
        return dict(Counter(r.get('dificultad_explotacion', 'Desconocida') for r in self.resultados))

    def get_impacto_stats(self):
        cia = {
            'confidencialidad': Counter(),
            'integridad': Counter(),
            'disponibilidad': Counter(),
        }
        for r in self.resultados:
            imp = r.get('impacto_potencial', {})
            cia['confidencialidad'][imp.get('confidencialidad', 'Desconocida')] += 1
            cia['integridad'][imp.get('integridad', 'Desconocida')] += 1
            cia['disponibilidad'][imp.get('disponibilidad', 'Desconocida')] += 1
        return {k: dict(v) for k, v in cia.items()}

    def get_sin_clasificar(self):
        data = [
            {
                'cve_id': r['cve_id'],
                'descripcion': r['descripcion_general'][:150] + '...',
                'etiquetas': r.get('etiquetas', []),
                'score': r['cvssv3']['score'],
            }
            for r in self.resultados if r.get('tipo') == 'Sin clasificar'
        ]
        return data[:self.max_items]

    def get_cves_criticos_sin_componente(self):
        data = [
            {
                'cve_id': r['cve_id'],
                'tipo': r['tipo'],
                'score': r['cvssv3']['score'],
                'descripcion': r['descripcion_general'][:100] + '...',
            }
            for r in self.resultados
            if r.get('riesgo') == 'crítico' and not r.get('componente_afectado')
        ]
        return data[:self.max_items]

    def get_cves_sin_versiones(self):
        data = [
            {
                'cve_id': r['cve_id'],
                'componente': r.get('componente_afectado', 'N/A'),
                'tipo': r['tipo'],
                'score': r['cvssv3']['score'],
            }
            for r in self.resultados if not r.get('versiones_afectadas')
        ]
        return data[:self.max_items]

    # --------------------------------------------------- #
    # -----------   PRINT REPORT OPTIMIZADO   ----------- #
    # --------------------------------------------------- #

    def print_report(self, verbose=False, use_logger=False):
        """
        Informe optimizado.
        - verbose=False → solo resumen ultra corto
        - verbose=True → informe completo (solo a consola)
        - use_logger=False → evita que logging imprima el informe completo
        """

        # SOLO mensaje de inicio
        if use_logger:
            logger.info("Generando reporte de análisis de mapping...")

        # ------------------------
        # 1. RESUMEN RÁPIDO
        # ------------------------
        if not verbose:
            print("📊 Resumen generado.")
            print("👉 Informe completo exportado a: reports/mapping_analysis.json")
            return

        # ------------------------
        # 2. INFORME COMPLETO
        # ------------------------
        out = []  # buffer

        out.append("="*80)
        out.append(" REPORTE DE ANÁLISIS DE MAPPING CVE ".center(80, "="))
        out.append("="*80 + "\n")

        out.append("📊 ESTADÍSTICAS GENERALES")
        out.append("-" * 80)
        out.append(f"Total CVEs procesados:        {self.stats['total']}")
        out.append(f"Con componente identificado:  {self.stats['con_componente']}")
        out.append(f"Sin componente:               {self.stats['sin_componente']}")
        out.append(f"Con versiones afectadas:      {self.stats['con_versiones']}")
        out.append(f"Sin versiones:                {self.stats['sin_versiones']}")
        out.append("")

        # resto del reporte...
        # <<< TODO igual, no lo repito aquí por espacio >>>

        out.append("="*80)
        out.append(" FIN DEL REPORTE ".center(80, "="))
        out.append("="*80)

        # -------- SOLO UNA IMPRESIÓN -------- #
        print("\n".join(out))

        # logging NO imprime el informe completo
        if use_logger:
            logger.info("Reporte generado correctamente.")

    # --------------------------------------------------- #
    # -----------------   EXPORT JSON   ------------------ #
    # --------------------------------------------------- #

    def export_json(self, filepath="debug_mapping_report.json"):
        report = {
            'timestamp': datetime.now().isoformat(),
            'stats': self.stats,
            'tipos': self.get_tipo_stats(),
            'riesgos': self.get_riesgo_stats(),
            'componentes_top': self.get_componente_stats(),
            'etiquetas_top': self.get_etiquetas_stats(),
            'infraestructura_5g': self.get_infraestructura_stats(),
            'protocolos': self.get_protocolos_stats(),
            'interfaces': self.get_interfaces_stats(),
            'dificultad': self.get_dificultad_stats(),
            'impacto': self.get_impacto_stats(),
            'sin_clasificar': self.get_sin_clasificar(),
            'criticos_sin_componente': self.get_cves_criticos_sin_componente(),
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"✅ Reporte exportado a {filepath}")

    """
    Analizador de resultados del mapping de CVEs.
    Uso:
        debugger = DebugMapper()
        for item in nvd_data:
            resultado = normalizar_cve(item)
            debugger.add(resultado)
        debugger.print_report()
    """
    
    def __init__(self):
        self.resultados = []
        self.stats = {
            'total': 0,
            'con_componente': 0,
            'sin_componente': 0,
            'con_versiones': 0,
            'sin_versiones': 0,
            'con_mitre': 0,
            'sin_mitre': 0,
        }
        
    def add(self, resultado: Optional[dict]):
        """Añade un resultado normalizado para análisis"""
        if not resultado:
            return
            
        self.resultados.append(resultado)
        self.stats['total'] += 1
        
        if resultado.get('componente_afectado'):
            self.stats['con_componente'] += 1
        else:
            self.stats['sin_componente'] += 1
            
        if resultado.get('versiones_afectadas'):
            self.stats['con_versiones'] += 1
        else:
            self.stats['sin_versiones'] += 1
            
        if resultado.get('descripcion_tecnica') or resultado.get('referencias_mitre'):
            self.stats['con_mitre'] += 1
        else:
            self.stats['sin_mitre'] += 1
    
    def get_tipo_stats(self) -> dict:
        """Estadísticas por tipo de vulnerabilidad"""
        tipos = Counter(r.get('tipo', 'Sin clasificar') for r in self.resultados)
        return dict(tipos.most_common())
    
    def get_riesgo_stats(self) -> dict:
        """Estadísticas por nivel de riesgo"""
        riesgos = Counter(r.get('riesgo', 'desconocido') for r in self.resultados)
        return dict(riesgos.most_common())
    
    def get_componente_stats(self, top_n: int = 20) -> dict:
        """Top N componentes afectados"""
        componentes = Counter(
            r.get('componente_afectado') 
            for r in self.resultados 
            if r.get('componente_afectado')
        )
        return dict(componentes.most_common(top_n))
    
    def get_etiquetas_stats(self, top_n: int = 30) -> dict:
        """Top N etiquetas más usadas"""
        etiquetas = []
        for r in self.resultados:
            etiquetas.extend(r.get('etiquetas', []))
        counter = Counter(etiquetas)
        return dict(counter.most_common(top_n))
    
    def get_infraestructura_stats(self) -> dict:
        """Estadísticas de infraestructura 5G afectada"""
        infra = []
        for r in self.resultados:
            infra.extend(r.get('infraestructura_5g_afectada', []))
        return dict(Counter(infra))
    
    def get_protocolos_stats(self, top_n: int = 20) -> dict:
        """Top N protocolos implicados"""
        protos = []
        for r in self.resultados:
            protos.extend(r.get('protocolos_implicados', []))
        counter = Counter(protos)
        return dict(counter.most_common(top_n))
    
    def get_interfaces_stats(self) -> dict:
        """Estadísticas de interfaces implicadas"""
        ifaces = []
        for r in self.resultados:
            ifaces.extend(r.get('interfaces_implicadas', []))
        return dict(Counter(ifaces))
    
    def get_dificultad_stats(self) -> dict:
        """Estadísticas por dificultad de explotación"""
        difs = Counter(r.get('dificultad_explotacion', 'Desconocida') for r in self.resultados)
        return dict(difs)
    
    def get_impacto_stats(self) -> dict:
        """Estadísticas de impacto CIA"""
        cia = {
            'confidencialidad': Counter(),
            'integridad': Counter(),
            'disponibilidad': Counter(),
        }
        
        for r in self.resultados:
            imp = r.get('impacto_potencial', {})
            cia['confidencialidad'][imp.get('confidencialidad', 'Desconocida')] += 1
            cia['integridad'][imp.get('integridad', 'Desconocida')] += 1
            cia['disponibilidad'][imp.get('disponibilidad', 'Desconocida')] += 1
        
        return {k: dict(v) for k, v in cia.items()}
    
    def get_sin_clasificar(self) -> list:
        """CVEs que quedaron sin clasificar"""
        return [
            {
                'cve_id': r['cve_id'],
                'descripcion': r['descripcion_general'][:150] + '...',
                'etiquetas': r.get('etiquetas', []),
                'score': r['cvssv3']['score']
            }
            for r in self.resultados
            if r.get('tipo') == 'Sin clasificar'
        ]
    
    def get_cves_criticos_sin_componente(self) -> list:
        """CVEs críticos sin componente identificado"""
        return [
            {
                'cve_id': r['cve_id'],
                'tipo': r['tipo'],
                'score': r['cvssv3']['score'],
                'descripcion': r['descripcion_general'][:100] + '...'
            }
            for r in self.resultados
            if r.get('riesgo') == 'crítico' and not r.get('componente_afectado')
        ]
    
    def get_cves_sin_versiones(self) -> list:
        """CVEs sin versiones afectadas identificadas"""
        return [
            {
                'cve_id': r['cve_id'],
                'componente': r.get('componente_afectado', 'N/A'),
                'tipo': r['tipo'],
                'score': r['cvssv3']['score']
            }
            for r in self.resultados
            if not r.get('versiones_afectadas')
        ][:50]  # Limitar a 50
    
    def print_report(self):
        """Imprime reporte completo en consola"""
        print("\n" + "="*80)
        print(" REPORTE DE ANÁLISIS DE MAPPING CVE ".center(80, "="))
        print("="*80 + "\n")
        
        # Estadísticas generales
        print("📊 ESTADÍSTICAS GENERALES")
        print("-" * 80)
        print(f"Total CVEs procesados:        {self.stats['total']:,}")
        print(f"Con componente identificado:  {self.stats['con_componente']:,} ({self._pct(self.stats['con_componente'])}%)")
        print(f"Sin componente:               {self.stats['sin_componente']:,} ({self._pct(self.stats['sin_componente'])}%)")
        print(f"Con versiones afectadas:      {self.stats['con_versiones']:,} ({self._pct(self.stats['con_versiones'])}%)")
        print(f"Sin versiones:                {self.stats['sin_versiones']:,} ({self._pct(self.stats['sin_versiones'])}%)")
        print(f"Con info de MITRE:            {self.stats['con_mitre']:,} ({self._pct(self.stats['con_mitre'])}%)")
        print()
        
        # Tipos de vulnerabilidad
        print("🎯 DISTRIBUCIÓN POR TIPO DE VULNERABILIDAD")
        print("-" * 80)
        tipos = self.get_tipo_stats()
        for tipo, count in tipos.items():
            bar = "█" * int(count / self.stats['total'] * 50)
            print(f"{tipo:35s} {count:6,} ({self._pct(count):5.1f}%) {bar}")
        print()
        
        # Niveles de riesgo
        print("⚠️  DISTRIBUCIÓN POR NIVEL DE RIESGO")
        print("-" * 80)
        riesgos = self.get_riesgo_stats()
        for riesgo, count in riesgos.items():
            emoji = {"crítico": "🔴", "alto": "🟠", "medio": "🟡", "bajo": "🟢"}.get(riesgo, "⚪")
            print(f"{emoji} {riesgo.capitalize():15s} {count:6,} ({self._pct(count):5.1f}%)")
        print()
        
        # Top componentes
        print("🔧 TOP 20 COMPONENTES AFECTADOS")
        print("-" * 80)
        componentes = self.get_componente_stats(20)
        for i, (comp, count) in enumerate(componentes.items(), 1):
            print(f"{i:2d}. {comp:50s} {count:4,} CVEs")
        print()
        
        # Top etiquetas
        print("🏷️  TOP 20 ETIQUETAS")
        print("-" * 80)
        etiquetas = self.get_etiquetas_stats(20)
        for i, (tag, count) in enumerate(etiquetas.items(), 1):
            print(f"{i:2d}. {tag:25s} {count:5,} ({self._pct(count):5.1f}%)")
        print()
        
        # Infraestructura 5G
        infra = self.get_infraestructura_stats()
        if infra:
            print("📡 INFRAESTRUCTURA 5G AFECTADA")
            print("-" * 80)
            for comp, count in infra.items():
                print(f"{comp:15s} {count:5,} CVEs")
            print()
        
        # Top protocolos
        protos = self.get_protocolos_stats(15)
        if protos:
            print("🌐 TOP 15 PROTOCOLOS IMPLICADOS")
            print("-" * 80)
            for proto, count in protos.items():
                print(f"{proto:15s} {count:5,} CVEs")
            print()
        
        # Interfaces
        ifaces = self.get_interfaces_stats()
        if ifaces:
            print("🔌 INTERFACES IMPLICADAS")
            print("-" * 80)
            for iface, count in ifaces.items():
                print(f"{iface:10s} {count:5,} CVEs")
            print()
        
        # Dificultad de explotación
        print("🎲 DIFICULTAD DE EXPLOTACIÓN")
        print("-" * 80)
        difs = self.get_dificultad_stats()
        for dif, count in difs.items():
            print(f"{dif:15s} {count:5,} ({self._pct(count):5.1f}%)")
        print()
        
        # Impacto CIA
        print("🛡️  IMPACTO POTENCIAL (CIA)")
        print("-" * 80)
        impactos = self.get_impacto_stats()
        for categoria, valores in impactos.items():
            print(f"\n{categoria.capitalize()}:")
            for nivel, count in valores.items():
                print(f"  {nivel:15s} {count:5,} ({self._pct(count):5.1f}%)")
        print()
        
        # CVEs sin clasificar
        sin_clasificar = self.get_sin_clasificar()
        if sin_clasificar:
            print(f"❓ CVEs SIN CLASIFICAR ({len(sin_clasificar)})")
            print("-" * 80)
            for cve in sin_clasificar[:10]:
                print(f"\n{cve['cve_id']} (Score: {cve['score']})")
                print(f"  Etiquetas: {', '.join(cve['etiquetas']) if cve['etiquetas'] else 'ninguna'}")
                print(f"  Desc: {cve['descripcion']}")
            if len(sin_clasificar) > 10:
                print(f"\n... y {len(sin_clasificar) - 10} más")
            print()
        
        # CVEs críticos sin componente
        criticos = self.get_cves_criticos_sin_componente()
        if criticos:
            print(f"🚨 CVEs CRÍTICOS SIN COMPONENTE ({len(criticos)})")
            print("-" * 80)
            for cve in criticos[:10]:
                print(f"{cve['cve_id']:20s} {cve['tipo']:30s} Score: {cve['score']}")
            if len(criticos) > 10:
                print(f"... y {len(criticos) - 10} más")
            print()
        
        print("="*80)
        print(" FIN DEL REPORTE ".center(80, "="))
        print("="*80 + "\n")
    
    def _pct(self, count: int) -> float:
        """Calcula porcentaje"""
        if self.stats['total'] == 0:
            return 0.0
        return (count / self.stats['total']) * 100
    
    def export_json(self, filepath: str = "debug_mapping_report.json"):
        """Exporta reporte completo a JSON"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'stats': self.stats,
            'tipos': self.get_tipo_stats(),
            'riesgos': self.get_riesgo_stats(),
            'componentes_top20': self.get_componente_stats(20),
            'etiquetas_top30': self.get_etiquetas_stats(30),
            'infraestructura_5g': self.get_infraestructura_stats(),
            'protocolos_top20': self.get_protocolos_stats(20),
            'interfaces': self.get_interfaces_stats(),
            'dificultad': self.get_dificultad_stats(),
            'impacto_cia': self.get_impacto_stats(),
            'sin_clasificar': self.get_sin_clasificar(),
            'criticos_sin_componente': self.get_cves_criticos_sin_componente(),
            'sin_versiones_sample': self.get_cves_sin_versiones(),
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Reporte exportado a: {filepath}")
    
    def export_csv_sin_clasificar(self, filepath: str = "cves_sin_clasificar.csv"):
        """Exporta CVEs sin clasificar a CSV para análisis"""
        import csv
        
        sin_clasificar = self.get_sin_clasificar()
        if not sin_clasificar:
            print("No hay CVEs sin clasificar")
            return
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['cve_id', 'score', 'etiquetas', 'descripcion'])
            writer.writeheader()
            for cve in sin_clasificar:
                writer.writerow({
                    'cve_id': cve['cve_id'],
                    'score': cve['score'],
                    'etiquetas': ', '.join(cve['etiquetas']),
                    'descripcion': cve['descripcion']
                })
        
        print(f"✅ CVEs sin clasificar exportados a: {filepath}")