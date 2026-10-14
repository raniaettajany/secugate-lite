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
    raise NotImplementedError


def alerter(sig: Signal, verdict: Verdict, journal: list) -> Alerte:
    raise NotImplementedError


def valider_action(verdict: Verdict, reponse: str) -> bool:
    raise NotImplementedError