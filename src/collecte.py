from src.contrat import Signal
import re


def masquer_ip(ip: str) -> str:
    """Remplace le dernier nombre de l'adresse par x. Lève ValueError si != 4 parties."""
    parties = ip.split('.')
    if len(parties) != 4:
        raise ValueError(
            "L'adresse IP doit comporter 4 parties séparées par des points.")
    parties[3] = 'x'
    return '.'.join(parties)


def masquer_parametres(chemin: str) -> str:
    """Remplace la valeur des paramètres token, password, session et key par [MASQUE]."""
    pattern = re.compile(r'(?i)(token|password|session|key)=([^&\s]+)')
    return pattern.sub(r'\1=[MASQUE]', chemin)


def normaliser_acces(ligne: str, numero: int, cible: str = "web-app") -> Signal:
    """Normalise une ligne de log d'accès brute en un objet Signal."""
    champs = ligne.split()
    if len(champs) < 6:
        raise ValueError("La ligne de log a moins de 6 champs.")

    date, heure, ip, methode, chemin, statut = champs[
        0], champs[1], champs[2], champs[3], champs[4], champs[5]

    signal_id = f"SIG-{numero:05d}"
    timestamp = f"{date}T{heure}Z"

    chemin_sans_param = chemin.split('?')[0]
    chemin_masque = masquer_parametres(chemin)
    ip_masquee = masquer_ip(ip)

    # Type de signal
    if chemin_sans_param == "/login" and statut in ("401", "403"):
        sig_type = "LOGIN_ECHEC"
    else:
        sig_type = "ACCES"

    # Gravité
    if statut.startswith('5'):
        gravite = "ELEVEE"
    elif statut.startswith('4'):
        gravite = "MOYENNE"
    else:
        gravite = "FAIBLE"

    message = f"{methode} {chemin_masque} -> {statut} depuis {ip_masquee}"

    return Signal(
        id=signal_id,
        timestamp=timestamp,
        source="ACCES",
        ip=ip,
        cible=cible,
        type=sig_type,
        gravite=gravite,
        message=message
    )


def normaliser_scan(rapport: dict, numero: int) -> Signal:
    """Normalise un rapport de scan en un objet Signal."""
    cles_requises = ["rule", "component", "severity", "message", "date"]
    for cle in cles_requises:
        if cle not in rapport:
            raise ValueError(f"Clé manquante dans le rapport de scan : {cle}")

    signal_id = f"SIG-{numero:05d}"
    sev = rapport["severity"].lower()

    if sev == "blocker":
        gravite = "CRITIQUE"
    elif sev == "critical":
        gravite = "ELEVEE"
    elif sev == "major":
        gravite = "MOYENNE"
    else:
        gravite = "FAIBLE"

    message = f"Faille {rapport['rule']} {rapport['message']}"

    return Signal(
        id=signal_id,
        timestamp=rapport["date"],
        source="SCAN",
        ip="",
        cible=rapport["component"],
        type="FAILLE",
        gravite=gravite,
        message=message
    )
