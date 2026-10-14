from src.contrat import Alerte, Signal, Verdict


def choisir_canal(niveau: str) -> str:
    canaux = {
        "CRITIQUE": "TELEPHONE",
        "ELEVEE": "SLACK",
        "MOYENNE": "EMAIL",
        "FAIBLE": "TABLEAU",
    }
    if niveau not in canaux:
        raise ValueError(f"Niveau inconnu : {niveau}")
    return canaux[niveau]


def rediger(sig: Signal, verdict: Verdict) -> str:
    lignes = [
        f"[{verdict.niveau}] Cible : {sig.cible}",
        f"Signal : {sig.message}",
        f"Explication : {verdict.explication}",
        f"Action proposee : {verdict.action}",
        f"Sources : {', '.join(verdict.sources)}",
    ]
    return "\n".join(lignes)


def alerter(sig: Signal, verdict: Verdict, journal: list) -> Alerte:
    al = Alerte(
        signal_id=sig.id,
        canal=choisir_canal(verdict.niveau),
        destinataire="equipe-secu",
        texte=rediger(sig, verdict),
    )
    journal.append(al)
    sig.statut = "ALERTE"
    return al


def valider_action(verdict: Verdict, reponse: str) -> bool:
    if not verdict.sensible:
        return True
    rep = "".join(reponse.split()).lower()
    return rep in {"o", "oui", "ok", "yes"}