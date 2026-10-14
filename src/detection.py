from src.contrat import Signal, Verdict

def est_deja_vu(sig: Signal, vus: set) -> bool:
    """
    Clé = (timestamp, source, ip, cible, type, message).
    Renvoie True si la clé est déjà dans l'ensemble vus; sinon l'ajoute et renvoie False.
    """
    cle = (sig.timestamp, sig.source, sig.ip, sig.cible, sig.type, sig.message)
    if cle in vus:
        return True
    vus.add(cle)
    return False

def compter_echecs(sig: Signal, compteur: dict) -> int:
    """
    Si le type est LOGIN_ECHEC: ajoute 1 au compteur de son IP (dictionnaire IP -> nombre) 
    et renvoie le nouveau total. Sinon renvoie sans toucher au compteur.
    """
    if sig.type == "LOGIN_ECHEC":
        compteur[sig.ip] = compteur.get(sig.ip, 0) + 1
        return compteur[sig.ip]
    return compteur.get(sig.ip, 0)

def chercher_procedures(sig: Signal, base: dict) -> list:
    """
    Recherche simplifiée: renvoie la liste des procédures dont le mot-clé (clé de base) 
    figure dans le message, sans tenir compte de la casse, dans l'ordre de base; liste vide sinon.
    """
    resultats = []
    message_lower = sig.message.lower()
    for mot_cle, procedure in base.items():
        if mot_cle.lower() in message_lower:
            resultats.append(procedure)
    return resultats

def evaluer(sig: Signal, nb_echecs: int = 0) -> str:
    """
    Règles déterministes:
    (1) LOGIN_ECHEC: CRITIQUE si nb_echecs >= 5, sinon MOYENNE.
    (2) Sinon: la gravité du signal.
    """
    if sig.type == "LOGIN_ECHEC":
        if nb_echecs >= 5:
            return "CRITIQUE"
        else:
            return "MOYENNE"
    return sig.gravite

def analyser(sig: Signal, base: dict, nb_echecs: int = 0) -> Verdict:
    """
    Renvoie un Verdict:
    - niveau = evaluer(sig, nb_echecs)
    - explication = procédures trouvées jointes par " ", sinon "Cause inconnue analyse manuelle requise"
    - action = "Bloquer l'IP <ip>" (LOGIN_ECHEC de niveau CRITIQUE), "Corriger la faille dans <cible>" (FAILLE), sinon "Surveiller"
    - sensible = vrai si le niveau est ELEVEE ou CRITIQUE
    - sources = [sig.source]
    Passe sig.statut à ANALYSE.
    """
    niveau = evaluer(sig, nb_echecs)
    
    procedures = chercher_procedures(sig, base)
    if procedures:
        explication = " ".join(procedures)
    else:
        explication = "Cause inconnue analyse manuelle requise"
        
    if sig.type == "LOGIN_ECHEC" and niveau == "CRITIQUE":
        action = f"Bloquer l'IP {sig.ip}"
    elif sig.type == "FAILLE":
        action = f"Corriger la faille dans {sig.cible}"
    else:
        action = "Surveiller"
        
    sensible = niveau in ["ELEVEE", "CRITIQUE"]
    sources = [sig.source]
    
    sig.statut = "ANALYSE"
    
    return Verdict(
        signal_id=sig.id,
        niveau=niveau,
        explication=explication,
        action=action,
        sensible=sensible,
        sources=sources
    )