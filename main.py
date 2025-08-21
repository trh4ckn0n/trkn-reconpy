#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess, os, shutil
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import questionary
from rich.console import Console
from rich.progress import track
from datetime import datetime

console = Console()

# -----------------------------
# Configuration
# -----------------------------
TOOLS = {
    "nmap": "nmap",
    "httpx": "httpx",
    "nuclei": "nuclei",
    "dnsx": "dnsx",
    "alterx": "alterx",
    "dalfox": "dalfox"
}

THREADS = 10

def check_tools():
    for tool, cmd in TOOLS.items():
        if not shutil.which(cmd):
            console.print(f"[red]❌ {tool} n'est pas installé ou pas dans le PATH[/red]")
            exit(1)

def run_cmd(cmd, capture=False):
    """Exécute une commande shell"""
    console.print(f"[cyan]💻 Running:[/cyan] {cmd}")
    if capture:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout.strip()
    else:
        subprocess.run(cmd, shell=True)

def create_results_dir(target):
    path = Path(f"results_{target}")
    path.mkdir(exist_ok=True)
    return path

# -----------------------------
# Fonctions principales
# -----------------------------
def discover_subdomains(target, results_dir):
    console.print(f"[yellow]🌐 Découverte des sous-domaines pour {target}...[/yellow]")
    perm_file = results_dir / "permutations.txt"
    resolved_file = results_dir / "resolved.txt"
    
    run_cmd(f"echo {target} | alterx generate -o {perm_file} --silent")
    run_cmd(f"dnsx -l {perm_file} -resp-only > {resolved_file}")
    
    count = sum(1 for _ in open(resolved_file))
    console.print(f"[green]✅ {count} sous-domaines résolus[/green]")
    return resolved_file

def scan_http(resolved_file, results_dir):
    console.print("[yellow]🔗 Analyse HTTP des hôtes actifs...[/yellow]")
    http_targets = results_dir / "http_targets.txt"
    
    cmd = f"httpx -l {resolved_file} --follow-redirects --no-verify --timeout 10"
    
    # Multi-threaded
    urls = open(resolved_file).read().splitlines()
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        results = list(executor.map(lambda u: run_cmd(f"httpx -u {u} --follow-redirects --no-verify --timeout 10", capture=True), urls))
    
    with open(http_targets, "w") as f:
        for r in results:
            if r: f.write(r + "\n")
    
    count = sum(1 for _ in open(http_targets))
    console.print(f"[green]✅ {count} hôtes HTTP actifs détectés[/green]")
    return http_targets

def scan_vulns(http_targets, results_dir):
    console.print("[yellow]⚡ Scan de vulnérabilités (Nuclei)...[/yellow]")
    nuclei_file = results_dir / "nuclei_results.txt"
    run_cmd(f"nuclei -l {http_targets} -t ~/nuclei-templates/ -o {nuclei_file}")
    
    console.print("[yellow]⚡ Scan XSS avec Dalfox...[/yellow]")
    xss_file = results_dir / "dalfox_results.txt"
    run_cmd(f"dalfox file {http_targets} -o {xss_file}")
    
    console.print(f"[green]✅ Scans de vulnérabilités terminés[/green]")
    return nuclei_file, xss_file

def scan_nmap(resolved_file, results_dir):
    console.print("[yellow]🛡️ Scan Nmap avec scripts NSE...[/yellow]")
    nmap_file = results_dir / "nmap_results.txt"
    
    hosts = open(resolved_file).read().splitlines()
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        results = list(executor.map(lambda h: run_cmd(f"nmap -sV --script vuln {h}", capture=True), hosts))
    
    with open(nmap_file, "w") as f:
        for r in results:
            if r: f.write(r + "\n\n")
    
    console.print(f"[green]✅ Scan Nmap terminé[/green]")
    return nmap_file

def scrape_files(http_targets, results_dir):
    console.print("[yellow]🗂️ Scraping fichiers sensibles...[/yellow]")
    common_paths = ["admin", "login", "backup.zip", ".env", "config.php"]
    found_file = results_dir / "found_files.txt"
    
    urls = open(http_targets).read().splitlines()
    with open(found_file, "w") as f:
        for url in track(urls, description="Scanning paths..."):
            for path in common_paths:
                result = run_cmd(f"httpx -u {url}/{path} ", capture=True)
                if result:
                    f.write(result + "\n")
    console.print(f"[green]✅ Scraping terminé[/green]")
    return found_file

def generate_html_report(results_dir):
    console.print("[yellow]📄 Génération du rapport HTML...[/yellow]")
    html_file = results_dir / "report.html"
    with open(html_file, "w") as f:
        f.write("<html><head><title>Recon Report</title></head><body>")
        f.write(f"<h1>Recon Report - {datetime.now()}</h1>")
        for file in results_dir.iterdir():
            if file.suffix in [".txt"]:
                f.write(f"<h2>{file.name}</h2><pre>{open(file).read()}</pre>")
        f.write("</body></html>")
    console.print(f"[green]✅ Rapport HTML généré: {html_file}[/green]")

# -----------------------------
# Main
# -----------------------------
def main():
    target = questionary.text("🔍 Entrez le domaine cible:").ask()
    if not target:
        console.print("[red]❌ Aucun domaine saisi ![/red]")
        return

    results_dir = create_results_dir(target)
    
    resolved_file = discover_subdomains(target, results_dir)
    http_targets = scan_http(resolved_file, results_dir)
    nuclei_file, xss_file = scan_vulns(http_targets, results_dir)
    nmap_file = scan_nmap(resolved_file, results_dir)
    found_file = scrape_files(http_targets, results_dir)
    generate_html_report(results_dir)

    console.print(f"[cyan]📂 Tous les résultats sont dans : {results_dir}[/cyan]")

if __name__ == "__main__":
    check_tools()
    main()
