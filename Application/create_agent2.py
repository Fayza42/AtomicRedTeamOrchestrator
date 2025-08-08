def _clean_json_output(self, raw_output):
    """Nettoie la sortie du LLM pour n'extraire que le JSON."""
    match = re.search(r'```json\n(.*?)\n```', raw_output, re.DOTALL)
    if match:
        return match.group(1)
    return raw_output # Fallback si le format n'est pas respecté

def run(self, vulnhub_id, target_ip):
    print(f"\n--- DÉBUT DE L'ANALYSE POUR {vulnhub_id} SUR {target_ip} ---")

    # 1. Récupérer la documentation depuis le RAG
    print(f"[1/5] Récupération de la documentation pour '{vulnhub_id}'...")
    docs = self.retriever.get_relevant_documents(vulnhub_id)
    if not docs:
        print("✗ Aucune documentation trouvée. Arrêt.")
        return None
    vulhub_doc = docs[0].page_content
    print("✓ Documentation récupérée.")

    # 2. Extraire les informations de la doc avec le LLM
    print("[2/5] Extraction des informations clés de la documentation...")
    raw_extraction = self.extraction_chain.run(vulhub_doc=vulhub_doc)
    cleaned_extraction = self._clean_json_output(raw_extraction)
    try:
        extracted_info = json.loads(cleaned_extraction)
        print(f"✓ Informations extraites : {len(extracted_info['ports_exposed'])} port(s), {len(extracted_info['reproduction_commands'])} commande(s).")
    except json.JSONDecodeError:
        print(f"✗ Erreur de parsing JSON pour l'extraction : {cleaned_extraction}")
        return None
    
    # 3. Utiliser les outils pour la reconnaissance active
    print("[3/5] Lancement de la reconnaissance active...")
    # Scan de ports
    target_host = target_ip.split(':')[0]
    ports_to_scan = extracted_info.get("ports_exposed", [])
    scan_results = self.tools['network_scanner'](target_host, ports_to_scan)
    print(f"  - Scan de ports terminé : {scan_results}")

    # Probing HTTP
    probe_results = {}
    for command in extracted_info.get("reproduction_commands", []):
        # Remplacer l'IP placeholder par la vraie IP
        final_command = command.replace("your-ip:8080", target_ip).replace("your-ip", target_host)
        probe_results[final_command] = self.tools['http_prober'](final_command)
    print(f"  - Probing HTTP terminé.")

    # Enrichissement CVE
    cve_results = {}
    main_cve = extracted_info.get("cve_ids", [None])[0]
    if main_cve:
        cve_results = self.tools['cve_enricher'](main_cve)
        print(f"  - Enrichissement CVE terminé : {cve_results}")
    
    # 4. Synthèse et génération du rapport final
    print("[4/5] Synthèse des résultats et génération du plan d'attaque...")
    raw_analysis = self.analysis_chain.run(
        extracted_info=json.dumps(extracted_info, indent=2),
        scan_results=scan_results,
        probe_results=json.dumps(probe_results, indent=2),
        cve_results=cve_results
    )
    cleaned_analysis = self._clean_json_output(raw_analysis)
    try:
        final_report = json.loads(cleaned_analysis)
        print("✓ Rapport final généré.")
    except json.JSONDecodeError:
        print(f"✗ Erreur de parsing JSON pour le rapport final : {cleaned_analysis}")
        return None

    # 5. Affichage du résultat
    print("[5/5] Analyse terminée.")
    print("--- RAPPORT D'EXPLOITATION FINAL ---")
    print(json.dumps(final_report, indent=2))
    print("------------------------------------")
    
    return final_report