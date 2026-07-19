#!/usr/bin/env python3
"""Generate BAFRDP locale catalogs from the transport source."""
import ast
from pathlib import Path

PLUGIN = Path(__file__).resolve().parents[1] / "BAFRDP"


def extract_msgids() -> list[str]:
    tree = ast.parse((PLUGIN / "transport.py").read_text(encoding="utf-8"))
    found: list[str] = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "_noop"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)):
            text = node.args[0].value
            if text not in found:
                found.append(text)
    return found


DE = {
 "RDP (BAF broker)": "RDP (BAF-Broker)",
 "RDP protected by the XRDP Broker Authentication Framework: single-use handles issued by a trusted broker replace passwords.":
 "RDP, geschützt durch das XRDP Broker Authentication Framework: Einmal-Handles eines vertrauenswürdigen Brokers ersetzen Passwörter.",
 "BAF Broker": "BAF-Broker",
 "Broker issuance URL": "Broker-Ausstellungs-URL",
 "HTTPS endpoint of the trusted BAF broker issuance API":
 "HTTPS-Endpunkt der Ausstellungs-API des vertrauenswürdigen BAF-Brokers",
 "Broker CA bundle": "CA-Bündel des Brokers",
 "Path to the CA bundle that authenticates the broker":
 "Pfad zum CA-Bündel, das den Broker authentifiziert",
 "Client certificate": "Client-Zertifikat",
 "Path to this server's mutual-TLS client certificate":
 "Pfad zum Mutual-TLS-Client-Zertifikat dieses Servers",
 "Client private key": "Privater Client-Schlüssel",
 "Path to this server's mutual-TLS private key":
 "Pfad zum privaten Mutual-TLS-Schlüssel dieses Servers",
 "Handle registration backend": "Backend für die Handle-Registrierung",
 "How the assertion is registered with the desktop host":
 "Wie die Assertion beim Desktop-Host registriert wird",
 "SSH to the desktop host": "SSH zum Desktop-Host",
 "Local or forwarded socket": "Lokaler oder weitergeleiteter Socket",
 "SSH identity file": "SSH-Identitätsdatei",
 "Dedicated private key for the registration account; pair it with a forced command on the desktop host":
 "Dedizierter privater Schlüssel für das Registrierungskonto; mit einem erzwungenen Befehl (forced command) auf dem Desktop-Host kombinieren",
 "SSH known_hosts file": "SSH-known_hosts-Datei",
 "Pinned host keys of the desktop hosts":
 "Gepinnte Host-Schlüssel der Desktop-Hosts",
 "SSH user": "SSH-Benutzer",
 "Registration account on the desktop host":
 "Registrierungskonto auf dem Desktop-Host",
 "Handle socket path": "Pfad des Handle-Sockets",
 "Handle service socket for the socket backend":
 "Socket des Handle-Dienstes für das Socket-Backend",
 "Ingress channel": "Ingress-Kanal",
 "How the single-use handle reaches the desktop host":
 "Wie das Einmal-Handle den Desktop-Host erreicht",
 "One-time credential (password field)": "Einmal-Anmeldedaten (Passwortfeld)",
 "Routing token (load-balance-info)": "Routing-Token (load-balance-info)",
 "Handle lifetime (seconds)": "Handle-Gültigkeit (Sekunden)",
 "Validity window of the single-use handle (1-120)":
 "Gültigkeitsfenster des Einmal-Handles (1-120)",
 "Fixed BAF target": "Fester BAF-Zielname",
 "Optional fixed target identifier; when empty the machine name of the assigned desktop is used":
 "Optionaler fester Zielbezeichner; wenn leer, wird der Maschinenname des zugewiesenen Desktops verwendet",
 "The desktop service is not configured correctly. Please contact your administrator.":
 "Der Desktop-Dienst ist nicht korrekt konfiguriert. Bitte wenden Sie sich an Ihre Administration.",
 "The sign-on service is temporarily unavailable. Please try again in a moment.":
 "Der Anmeldedienst ist vorübergehend nicht verfügbar. Bitte versuchen Sie es gleich noch einmal.",
 "You are not authorized to open this desktop.":
 "Sie sind nicht berechtigt, diesen Desktop zu öffnen.",
 "The desktop could not be prepared for your session. Please try again or contact your administrator.":
 "Der Desktop konnte für Ihre Sitzung nicht vorbereitet werden. Bitte versuchen Sie es erneut oder wenden Sie sich an Ihre Administration.",
 "The requested desktop is not available.":
 "Der angeforderte Desktop ist nicht verfügbar.",
 "An unexpected error occurred while starting your desktop.":
 "Beim Starten Ihres Desktops ist ein unerwarteter Fehler aufgetreten.",
}

FR = {
 "RDP (BAF broker)": "RDP (courtier BAF)",
 "RDP protected by the XRDP Broker Authentication Framework: single-use handles issued by a trusted broker replace passwords.":
 "RDP protégé par le Broker Authentication Framework de XRDP : des identifiants à usage unique émis par un courtier de confiance remplacent les mots de passe.",
 "BAF Broker": "Courtier BAF",
 "Broker issuance URL": "URL d'émission du courtier",
 "HTTPS endpoint of the trusted BAF broker issuance API":
 "Point de terminaison HTTPS de l'API d'émission du courtier BAF de confiance",
 "Broker CA bundle": "Bundle CA du courtier",
 "Path to the CA bundle that authenticates the broker":
 "Chemin du bundle CA qui authentifie le courtier",
 "Client certificate": "Certificat client",
 "Path to this server's mutual-TLS client certificate":
 "Chemin du certificat client TLS mutuel de ce serveur",
 "Client private key": "Clé privée du client",
 "Path to this server's mutual-TLS private key":
 "Chemin de la clé privée TLS mutuelle de ce serveur",
 "Handle registration backend": "Backend d'enregistrement des handles",
 "How the assertion is registered with the desktop host":
 "Comment l'assertion est enregistrée auprès de l'hôte de bureau",
 "SSH to the desktop host": "SSH vers l'hôte de bureau",
 "Local or forwarded socket": "Socket local ou redirigé",
 "SSH identity file": "Fichier d'identité SSH",
 "Dedicated private key for the registration account; pair it with a forced command on the desktop host":
 "Clé privée dédiée au compte d'enregistrement ; à associer à une commande forcée sur l'hôte de bureau",
 "SSH known_hosts file": "Fichier known_hosts SSH",
 "Pinned host keys of the desktop hosts":
 "Clés d'hôte épinglées des hôtes de bureau",
 "SSH user": "Utilisateur SSH",
 "Registration account on the desktop host":
 "Compte d'enregistrement sur l'hôte de bureau",
 "Handle socket path": "Chemin du socket de handles",
 "Handle service socket for the socket backend":
 "Socket du service de handles pour le backend socket",
 "Ingress channel": "Canal d'entrée",
 "How the single-use handle reaches the desktop host":
 "Comment le handle à usage unique atteint l'hôte de bureau",
 "One-time credential (password field)":
 "Identifiant à usage unique (champ mot de passe)",
 "Routing token (load-balance-info)": "Jeton de routage (load-balance-info)",
 "Handle lifetime (seconds)": "Durée de vie du handle (secondes)",
 "Validity window of the single-use handle (1-120)":
 "Fenêtre de validité du handle à usage unique (1-120)",
 "Fixed BAF target": "Cible BAF fixe",
 "Optional fixed target identifier; when empty the machine name of the assigned desktop is used":
 "Identifiant de cible fixe facultatif ; si vide, le nom de machine du bureau attribué est utilisé",
 "The desktop service is not configured correctly. Please contact your administrator.":
 "Le service de bureau n'est pas correctement configuré. Veuillez contacter votre administrateur.",
 "The sign-on service is temporarily unavailable. Please try again in a moment.":
 "Le service d'authentification est temporairement indisponible. Veuillez réessayer dans un instant.",
 "You are not authorized to open this desktop.":
 "Vous n'êtes pas autorisé à ouvrir ce bureau.",
 "The desktop could not be prepared for your session. Please try again or contact your administrator.":
 "Le bureau n'a pas pu être préparé pour votre session. Veuillez réessayer ou contacter votre administrateur.",
 "The requested desktop is not available.":
 "Le bureau demandé n'est pas disponible.",
 "An unexpected error occurred while starting your desktop.":
 "Une erreur inattendue s'est produite au démarrage de votre bureau.",
}

IT = {
 "RDP (BAF broker)": "RDP (broker BAF)",
 "RDP protected by the XRDP Broker Authentication Framework: single-use handles issued by a trusted broker replace passwords.":
 "RDP protetto dal Broker Authentication Framework di XRDP: handle monouso emessi da un broker fidato sostituiscono le password.",
 "BAF Broker": "Broker BAF",
 "Broker issuance URL": "URL di emissione del broker",
 "HTTPS endpoint of the trusted BAF broker issuance API":
 "Endpoint HTTPS dell'API di emissione del broker BAF fidato",
 "Broker CA bundle": "Bundle CA del broker",
 "Path to the CA bundle that authenticates the broker":
 "Percorso del bundle CA che autentica il broker",
 "Client certificate": "Certificato client",
 "Path to this server's mutual-TLS client certificate":
 "Percorso del certificato client mutual-TLS di questo server",
 "Client private key": "Chiave privata del client",
 "Path to this server's mutual-TLS private key":
 "Percorso della chiave privata mutual-TLS di questo server",
 "Handle registration backend": "Backend di registrazione degli handle",
 "How the assertion is registered with the desktop host":
 "Come l'asserzione viene registrata presso l'host desktop",
 "SSH to the desktop host": "SSH verso l'host desktop",
 "Local or forwarded socket": "Socket locale o inoltrato",
 "SSH identity file": "File di identità SSH",
 "Dedicated private key for the registration account; pair it with a forced command on the desktop host":
 "Chiave privata dedicata all'account di registrazione; da abbinare a un comando forzato sull'host desktop",
 "SSH known_hosts file": "File known_hosts SSH",
 "Pinned host keys of the desktop hosts":
 "Chiavi host fissate degli host desktop",
 "SSH user": "Utente SSH",
 "Registration account on the desktop host":
 "Account di registrazione sull'host desktop",
 "Handle socket path": "Percorso del socket degli handle",
 "Handle service socket for the socket backend":
 "Socket del servizio handle per il backend socket",
 "Ingress channel": "Canale di ingresso",
 "How the single-use handle reaches the desktop host":
 "Come l'handle monouso raggiunge l'host desktop",
 "One-time credential (password field)":
 "Credenziale monouso (campo password)",
 "Routing token (load-balance-info)":
 "Token di instradamento (load-balance-info)",
 "Handle lifetime (seconds)": "Durata dell'handle (secondi)",
 "Validity window of the single-use handle (1-120)":
 "Finestra di validità dell'handle monouso (1-120)",
 "Fixed BAF target": "Destinazione BAF fissa",
 "Optional fixed target identifier; when empty the machine name of the assigned desktop is used":
 "Identificatore di destinazione fisso facoltativo; se vuoto viene usato il nome macchina del desktop assegnato",
 "The desktop service is not configured correctly. Please contact your administrator.":
 "Il servizio desktop non è configurato correttamente. Contattare l'amministratore.",
 "The sign-on service is temporarily unavailable. Please try again in a moment.":
 "Il servizio di accesso è temporaneamente non disponibile. Riprovare tra qualche istante.",
 "You are not authorized to open this desktop.":
 "Non si è autorizzati ad aprire questo desktop.",
 "The desktop could not be prepared for your session. Please try again or contact your administrator.":
 "Non è stato possibile preparare il desktop per la sessione. Riprovare o contattare l'amministratore.",
 "The requested desktop is not available.":
 "Il desktop richiesto non è disponibile.",
 "An unexpected error occurred while starting your desktop.":
 "Si è verificato un errore imprevisto durante l'avvio del desktop.",
}

ES = {
 "RDP (BAF broker)": "RDP (bróker BAF)",
 "RDP protected by the XRDP Broker Authentication Framework: single-use handles issued by a trusted broker replace passwords.":
 "RDP protegido por el Broker Authentication Framework de XRDP: identificadores de un solo uso emitidos por un bróker de confianza sustituyen a las contraseñas.",
 "BAF Broker": "Bróker BAF",
 "Broker issuance URL": "URL de emisión del bróker",
 "HTTPS endpoint of the trusted BAF broker issuance API":
 "Punto de acceso HTTPS de la API de emisión del bróker BAF de confianza",
 "Broker CA bundle": "Paquete CA del bróker",
 "Path to the CA bundle that authenticates the broker":
 "Ruta del paquete CA que autentica al bróker",
 "Client certificate": "Certificado de cliente",
 "Path to this server's mutual-TLS client certificate":
 "Ruta del certificado de cliente TLS mutuo de este servidor",
 "Client private key": "Clave privada del cliente",
 "Path to this server's mutual-TLS private key":
 "Ruta de la clave privada TLS mutua de este servidor",
 "Handle registration backend": "Backend de registro de handles",
 "How the assertion is registered with the desktop host":
 "Cómo se registra la aserción en el host de escritorio",
 "SSH to the desktop host": "SSH al host de escritorio",
 "Local or forwarded socket": "Socket local o reenviado",
 "SSH identity file": "Archivo de identidad SSH",
 "Dedicated private key for the registration account; pair it with a forced command on the desktop host":
 "Clave privada dedicada a la cuenta de registro; combínela con un comando forzado en el host de escritorio",
 "SSH known_hosts file": "Archivo known_hosts de SSH",
 "Pinned host keys of the desktop hosts":
 "Claves de host fijadas de los hosts de escritorio",
 "SSH user": "Usuario SSH",
 "Registration account on the desktop host":
 "Cuenta de registro en el host de escritorio",
 "Handle socket path": "Ruta del socket de handles",
 "Handle service socket for the socket backend":
 "Socket del servicio de handles para el backend de socket",
 "Ingress channel": "Canal de entrada",
 "How the single-use handle reaches the desktop host":
 "Cómo llega el handle de un solo uso al host de escritorio",
 "One-time credential (password field)":
 "Credencial de un solo uso (campo de contraseña)",
 "Routing token (load-balance-info)":
 "Token de enrutamiento (load-balance-info)",
 "Handle lifetime (seconds)": "Vida del handle (segundos)",
 "Validity window of the single-use handle (1-120)":
 "Ventana de validez del handle de un solo uso (1-120)",
 "Fixed BAF target": "Destino BAF fijo",
 "Optional fixed target identifier; when empty the machine name of the assigned desktop is used":
 "Identificador de destino fijo opcional; si está vacío se usa el nombre de máquina del escritorio asignado",
 "The desktop service is not configured correctly. Please contact your administrator.":
 "El servicio de escritorio no está configurado correctamente. Póngase en contacto con su administrador.",
 "The sign-on service is temporarily unavailable. Please try again in a moment.":
 "El servicio de inicio de sesión no está disponible temporalmente. Inténtelo de nuevo en un momento.",
 "You are not authorized to open this desktop.":
 "No está autorizado a abrir este escritorio.",
 "The desktop could not be prepared for your session. Please try again or contact your administrator.":
 "No se pudo preparar el escritorio para su sesión. Inténtelo de nuevo o póngase en contacto con su administrador.",
 "The requested desktop is not available.":
 "El escritorio solicitado no está disponible.",
 "An unexpected error occurred while starting your desktop.":
 "Se ha producido un error inesperado al iniciar su escritorio.",
}


def po_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def write_po(language: str, translations: dict[str, str] | None,
             msgids: list[str]) -> None:
    lines = [
        '# BAF RDP transport portal strings.',
        '# Regenerate with tools/update-locales.py after editing',
        '# transport.py; msgids are extracted from the source.',
        'msgid ""',
        'msgstr ""',
        f'"Project-Id-Version: xrdp-baf-openuds\\n"',
        f'"Language: {language}\\n"',
        '"MIME-Version: 1.0\\n"',
        '"Content-Type: text/plain; charset=UTF-8\\n"',
        '"Content-Transfer-Encoding: 8bit\\n"',
        '',
    ]
    missing = []
    for msgid in msgids:
        if translations is None:
            msgstr = msgid
        else:
            msgstr = translations.get(msgid)
            if msgstr is None:
                missing.append(msgid)
                continue
        lines.append(f'msgid "{po_escape(msgid)}"')
        lines.append(f'msgstr "{po_escape(msgstr)}"')
        lines.append('')
    if missing:
        raise SystemExit(
            f"{language}: missing translations for: {missing!r}")
    out = PLUGIN / "locale" / language / "LC_MESSAGES" / "django.po"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {out} ({len(msgids)} entries)")


def main() -> None:
    msgids = extract_msgids()
    print(f"extracted {len(msgids)} msgids")
    write_po("en", None, msgids)
    write_po("de", DE, msgids)
    write_po("fr", FR, msgids)
    write_po("it", IT, msgids)
    write_po("es", ES, msgids)


if __name__ == "__main__":
    main()
