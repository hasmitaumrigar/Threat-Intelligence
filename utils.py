def classify_risk(score):

    if score >= 70:
        return "High Risk"

    elif score >= 30:
        return "Medium Risk"

    else:
        return "Low Risk"
    

