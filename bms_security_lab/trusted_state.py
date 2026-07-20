class TrustedBMSState:
    def __init__(self, soc_percent: float = 50.0) -> None:
        self._soc_percent = soc_percent

    def get_soc(self) -> float:
        return self._soc_percent
    
    def update_soc(self, soc_percent: float) -> None:
        if not 0.0 <= soc_percent <= 100.0:
            raise ValueError("Trusted SOC must be between 0 and 100")
        
        self._soc_percent = soc_percent